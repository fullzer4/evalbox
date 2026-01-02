════════════════════════════════════════════════════════════════════════════════
                         ARQUITETURA LEEWARD v1
════════════════════════════════════════════════════════════════════════════════


                              VISÃO GERAL
────────────────────────────────────────────────────────────────────────────────

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   CLIENT (Python/Node/Go/Rust)                                              │
│   │                                                                         │
│   │  1. Prepara arquivos em /data/jobs/{job_id}/input/                      │
│   │  2. Chama leeward via FFI                                               │
│   │  3. Recebe resultado                                                    │
│   │  4. Lê output de /data/jobs/{job_id}/output/                            │
│   │                                                                         │
│   ▼                                                                         │
│   libleeward.so (C FFI)                                                     │
│   │                                                                         │
│   │  - Serializa request (msgpack)                                          │
│   │  - Envia via Unix socket                                                │
│   │  - Deserializa response                                                 │
│   │                                                                         │
└───┼─────────────────────────────────────────────────────────────────────────┘
    │
    │  Unix socket: /var/run/leeward.sock
    │  Protocolo: [4 bytes len][msgpack payload]
    │  Tamanho: ~200 bytes (só metadata, não dados)
    │
┌───┼─────────────────────────────────────────────────────────────────────────┐
│   ▼                                                                         │
│   DAEMON (leeward-daemon)                                                   │
│   │                                                                         │
│   ├── Server (tokio async)                                                  │
│   │   │                                                                     │
│   │   ├── Aceita conexões                                                   │
│   │   ├── Deserializa requests                                              │
│   │   ├── Valida paths (allowed_paths check)                                │
│   │   └── Dispatch para worker pool                                         │
│   │                                                                         │
│   ├── Worker Pool                                                           │
│   │   │                                                                     │
│   │   ├── [W1] ──┐                                                          │
│   │   ├── [W2] ──┼── Processos pre-forked, isolados, Python quente          │
│   │   ├── [W3] ──┤                                                          │
│   │   └── [W4] ──┘                                                          │
│   │                                                                         │
│   └── Supervisor                                                            │
│       │                                                                     │
│       ├── seccomp-notify handler                                            │
│       ├── Timeout enforcer                                                  │
│       └── Metrics collector                                                 │
│                                                                             │
└───┼─────────────────────────────────────────────────────────────────────────┘
    │
    │  pipe (código + config, ~200 bytes)
    │
┌───┼─────────────────────────────────────────────────────────────────────────┐
│   ▼                                                                         │
│   WORKER (processo isolado)                                                 │
│   │                                                                         │
│   ├── Namespaces: user, pid, mount, net, ipc, uts                           │
│   ├── Bind mounts: /input (ro), /output (rw), /usr (ro)                     │
│   ├── Landlock: só acessa paths permitidos                                  │
│   ├── Seccomp: whitelist de ~30 syscalls                                    │
│   ├── Cgroups: memory, cpu, pids limits                                     │
│   │                                                                         │
│   └── Python interpreter                                                    │
│       │                                                                     │
│       ├── pandas, numpy pre-loaded                                          │
│       ├── Executa código do usuário                                         │
│       └── Retorna stdout/stderr/exit_code                                   │
│                                                                             │
└───┼─────────────────────────────────────────────────────────────────────────┘
    │
    │  bind mount (zero-copy, mesmo inode)
    │
┌───┼─────────────────────────────────────────────────────────────────────────┐
│   ▼                                                                         │
│   FILESYSTEM (host)                                                         │
│                                                                             │
│   /data/jobs/{job_id}/                                                      │
│   ├── input/                  ← client coloca arquivos aqui                 │
│   │   ├── vendas.xlsx (2GB)      worker lê via bind mount                   │
│   │   └── config.json                                                       │
│   └── output/                 ← worker escreve aqui                         │
│       └── resultado.parquet      client lê direto                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘



                           FLUXO DE EXECUÇÃO
────────────────────────────────────────────────────────────────────────────────

 TEMPO     CLIENT              FFI                 DAEMON              WORKER
───────────────────────────────────────────────────────────────────────────────

  0ms   ┌─────────────┐
        │ Prepara job │
        │ em /data/   │
        └──────┬──────┘
               │
  1ms          │         ┌─────────────┐
               └────────►│ serialize   │
                         │ request     │
                         └──────┬──────┘
                                │
  2ms                           │         ┌─────────────┐
                                └────────►│ recv socket │
                                          │ parse msg   │
                                          │ validate    │
                                          └──────┬──────┘
                                                 │
  3ms                                            │         ┌─────────────┐
                                                 └────────►│ recv pipe   │
                                                           │ setup mounts│
                                                           └──────┬──────┘
                                                                  │
  4ms                                                             │
        ┌─────────────────────────────────────────────────────────┘
        │
        ▼
  ┌───────────────────────────────────────────────────────────────────────┐
  │                                                                       │
  │   SANDBOX EXECUTION                                                   │
  │                                                                       │
  │   /input/vendas.xlsx ◄─── bind mount ◄─── /data/jobs/abc/input/       │
  │         │                                                             │
  │         ▼                                                             │
  │   df = pd.read_excel('/input/vendas.xlsx')   # zero-copy read         │
  │   summary = df.groupby('region').sum()                                │
  │   summary.to_parquet('/output/result.parquet')                        │
  │         │                                                             │
  │         ▼                                                             │
  │   /output/result.parquet ──► bind mount ──► /data/jobs/abc/output/    │
  │                                                                       │
  └───────────────────────────────────────────────────────────────────────┘
        │
        │ (tempo de execução variável)
        │
  Nms   │
        └────────────────────────────────────────┐
                                                 │
                                                 ▼
                                          ┌─────────────┐
                                          │ collect     │
                                          │ stdout/err  │
                                          │ metrics     │
                                          └──────┬──────┘
                                                 │
                                │◄───────────────┘
                                │
                         ┌──────┴──────┐
                         │ serialize   │
                         │ response    │
                         └──────┬──────┘
                                │
               │◄───────────────┘
               │
        ┌──────┴──────┐
        │ return      │
        │ result      │
        └──────┬──────┘
               │
               ▼
        ┌─────────────┐
        │ Lê output   │
        │ de /data/   │
        └─────────────┘



                              PROTOCOLO
────────────────────────────────────────────────────────────────────────────────

REQUEST (Client → Daemon)
┌────────────────────────────────────────────────────────────────────────────┐
│                                                                            │
│  ┌──────────┬──────────────────────────────────────────────────────────┐   │
│  │ 4 bytes  │  msgpack payload                                         │   │
│  │ (length) │                                                          │   │
│  └──────────┴──────────────────────────────────────────────────────────┘   │
│                                                                            │
│  {                                                                         │
│    "type": "Execute",                                                      │
│    "code": "df = pd.read_excel('/input/data.xlsx')...",                    │
│    "mounts": [                                                             │
│      {"host": "/data/jobs/abc/input", "sandbox": "/input", "ro": true},    │
│      {"host": "/data/jobs/abc/output", "sandbox": "/output", "ro": false}  │
│    ],                                                                      │
│    "timeout_secs": 300,                                                    │
│    "memory_limit": 4294967296                                              │
│  }                                                                         │
│                                                                            │
│  ~200 bytes                                                                │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘


RESPONSE (Daemon → Client)
┌────────────────────────────────────────────────────────────────────────────┐
│                                                                            │
│  ┌──────────┬──────────────────────────────────────────────────────────┐   │
│  │ 4 bytes  │  msgpack payload                                         │   │
│  │ (length) │                                                          │   │
│  └──────────┴──────────────────────────────────────────────────────────┘   │
│                                                                            │
│  {                                                                         │
│    "type": "Execute",                                                      │
│    "success": true,                                                        │
│    "result": {                                                             │
│      "exit_code": 0,                                                       │
│      "stdout": "Processed 1000000 rows",                                   │
│      "stderr": "",                                                         │
│      "duration_ms": 45230,                                                 │
│      "memory_peak": 3221225472,                                            │
│      "cpu_time_us": 44890000,                                              │
│      "timed_out": false,                                                   │
│      "oom_killed": false                                                   │
│    }                                                                       │
│  }                                                                         │
│                                                                            │
│  ~500 bytes                                                                │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘



                         ISOLAMENTO (WORKER)
────────────────────────────────────────────────────────────────────────────────

ORDEM DE APLICAÇÃO (crítico para segurança):

  1. CLONE/UNSHARE
     ┌─────────────────────────────────────────────────────────────────────┐
     │ clone3(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS |                 │
     │        CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS)                  │
     │                                                                     │
     │ → Processo em novos namespaces                                      │
     │ → UID 0 dentro = UID 1000 fora (mapeado)                            │
     └─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
  2. FILESYSTEM SETUP
     ┌─────────────────────────────────────────────────────────────────────┐
     │ mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)                 │
     │                                                                     │
     │ // Bind mounts                                                      │
     │ mount("/data/jobs/abc/input", "/sandbox/input", NULL, MS_BIND, NULL)│
     │ mount(NULL, "/sandbox/input", NULL, MS_REMOUNT | MS_RDONLY, NULL)   │
     │ mount("/data/jobs/abc/output", "/sandbox/output", NULL, MS_BIND, 0) │
     │                                                                     │
     │ // Sistema read-only                                                │
     │ mount("/usr", "/sandbox/usr", NULL, MS_BIND | MS_RDONLY, NULL)      │
     │ mount("/lib", "/sandbox/lib", NULL, MS_BIND | MS_RDONLY, NULL)      │
     │                                                                     │
     │ // tmpfs para temp                                                  │
     │ mount("tmpfs", "/sandbox/tmp", "tmpfs", 0, "size=100M")             │
     │                                                                     │
     │ // pivot_root                                                       │
     │ pivot_root("/sandbox", "/sandbox/.old")                             │
     │ umount2("/.old", MNT_DETACH)                                        │
     └─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
  3. LANDLOCK
     ┌─────────────────────────────────────────────────────────────────────┐
     │ ruleset_fd = landlock_create_ruleset(&attr, size, 0)                │
     │                                                                     │
     │ // Permite leitura                                                  │
     │ landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,           │
     │                   {.allowed_access = READ, .parent_fd = /input})    │
     │ landlock_add_rule(..., {READ, /usr})                                │
     │ landlock_add_rule(..., {READ, /lib})                                │
     │                                                                     │
     │ // Permite escrita                                                  │
     │ landlock_add_rule(..., {READ | WRITE, /output})                     │
     │ landlock_add_rule(..., {READ | WRITE, /tmp})                        │
     │                                                                     │
     │ landlock_restrict_self(ruleset_fd, 0)                               │
     └─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
  4. CAPABILITIES DROP
     ┌─────────────────────────────────────────────────────────────────────┐
     │ cap_clear(caps)                                                     │
     │ cap_set_proc(caps)                                                  │
     │                                                                     │
     │ prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)                              │
     └─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
  5. SECCOMP (último - trava interface de syscalls)
     ┌─────────────────────────────────────────────────────────────────────┐
     │ BPF filter (whitelist):                                             │
     │                                                                     │
     │ ALLOW: read, write, close, fstat, lseek, mmap, mprotect,            │
     │        munmap, brk, rt_sigaction, rt_sigprocmask, ioctl,            │
     │        access, dup, dup2, getpid, getuid, getgid, geteuid,          │
     │        getegid, fcntl, openat, newfstatat, exit, exit_group,        │
     │        futex, getrandom, clock_gettime, clock_nanosleep             │
     │                                                                     │
     │ DENY (with EACCES via notify): everything else                      │
     │                                                                     │
     │ seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER,  │
     │         &prog)                                                      │
     └─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
  6. CGROUPS
     ┌─────────────────────────────────────────────────────────────────────┐
     │ // Daemon já criou cgroup antes do fork                             │
     │ /sys/fs/cgroup/leeward/worker-{id}/                                 │
     │                                                                     │
     │ memory.max = 4294967296      (4GB)                                  │
     │ memory.swap.max = 0          (no swap)                              │
     │ cpu.max = 100000 100000      (100%)                                 │
     │ pids.max = 64                (max processes)                        │
     │                                                                     │
     │ // Worker adicionado ao cgroup                                      │
     │ echo $PID > /sys/fs/cgroup/leeward/worker-{id}/cgroup.procs         │
     └─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
  7. EXEC PYTHON
     ┌─────────────────────────────────────────────────────────────────────┐
     │ execve("/usr/bin/python3", ["python3", "-c", code], env)            │
     └─────────────────────────────────────────────────────────────────────┘



                        WORKER POOL LIFECYCLE
────────────────────────────────────────────────────────────────────────────────

STARTUP
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  Daemon                                                                     │
│     │                                                                       │
│     ├──► fork() ──► Worker 1 ──► setup isolation ──► Python ready (idle)   │
│     ├──► fork() ──► Worker 2 ──► setup isolation ──► Python ready (idle)   │
│     ├──► fork() ──► Worker 3 ──► setup isolation ──► Python ready (idle)   │
│     └──► fork() ──► Worker 4 ──► setup isolation ──► Python ready (idle)   │
│                                                                             │
│  Pool: [W1:idle] [W2:idle] [W3:idle] [W4:idle]                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


REQUEST HANDLING
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  Request chega                                                              │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐            │
│  │ Pool: [W1:idle] [W2:idle] [W3:idle] [W4:idle]               │            │
│  │              │                                              │            │
│  │              └──► grab W1                                   │            │
│  │                                                             │            │
│  │ Pool: [W1:busy] [W2:idle] [W3:idle] [W4:idle]               │            │
│  └─────────────────────────────────────────────────────────────┘            │
│       │                                                                     │
│       ├──► send code via pipe                                               │
│       │                                                                     │
│       │    W1 executes...                                                   │
│       │                                                                     │
│       ◄──► recv result via pipe                                             │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐            │
│  │ W1.execution_count++                                        │            │
│  │                                                             │            │
│  │ if execution_count >= 100:                                  │            │
│  │     recycle(W1)  # kill + respawn                           │            │
│  │ else:                                                       │            │
│  │     W1.state = idle                                         │            │
│  │                                                             │            │
│  │ Pool: [W1:idle] [W2:idle] [W3:idle] [W4:idle]               │            │
│  └─────────────────────────────────────────────────────────────┘            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


RECYCLING
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  Por que reciclar:                                                          │
│  - Memory leaks no Python                                                   │
│  - Estado poluído entre execuções                                           │
│  - Segurança (limpa qualquer state residual)                                │
│                                                                             │
│  recycle(W1):                                                               │
│       │                                                                     │
│       ├──► W1.state = recycling                                             │
│       ├──► kill(W1.pid, SIGKILL)                                            │
│       ├──► waitpid(W1.pid)                                                  │
│       ├──► destroy_cgroup(W1)                                               │
│       ├──► fork() ──► new W1                                                │
│       ├──► setup isolation                                                  │
│       └──► W1.state = idle, W1.execution_count = 0                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘



                              ESTRUTURA
────────────────────────────────────────────────────────────────────────────────

CRATES
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  leeward-core                                                               │
│  ├── src/                                                                   │
│  │   ├── lib.rs                                                             │
│  │   ├── config.rs         # SandboxConfig                                  │
│  │   ├── error.rs          # LeewardError                                   │
│  │   ├── result.rs         # ExecutionResult                                │
│  │   ├── worker.rs         # Worker struct                                  │
│  │   └── isolation/                                                         │
│  │       ├── mod.rs                                                         │
│  │       ├── namespace.rs  # clone/unshare                                  │
│  │       ├── mounts.rs     # bind mounts, pivot_root                        │
│  │       ├── landlock.rs   # filesystem restrictions                        │
│  │       ├── seccomp.rs    # syscall filter                                 │
│  │       └── cgroups.rs    # resource limits                                │
│  │                                                                          │
│  leeward-daemon                                                             │
│  ├── src/                                                                   │
│  │   ├── main.rs           # tokio server                                   │
│  │   ├── config.rs         # DaemonConfig                                   │
│  │   ├── server.rs         # socket handler                                 │
│  │   ├── pool.rs           # WorkerPool                                     │
│  │   └── protocol.rs       # msgpack Request/Response                       │
│  │                                                                          │
│  leeward-ffi                                                                │
│  ├── src/lib.rs            # C FFI exports                                  │
│  ├── build.rs              # cbindgen                                       │
│  └── cbindgen.toml                                                          │
│  │                                                                          │
│  leeward-cli                                                                │
│  └── src/main.rs           # CLI tool                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


BINDINGS
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  bindings/                                                                  │
│  ├── python/                                                                │
│  │   ├── leeward/                                                           │
│  │   │   ├── __init__.py                                                    │
│  │   │   └── client.py     # ctypes wrapper                                 │
│  │   └── pyproject.toml                                                     │
│  │                                                                          │
│  ├── node/        (futuro)                                                  │
│  │   └── ...               # ffi-napi                                       │
│  │                                                                          │
│  └── go/          (futuro)                                                  │
│      └── ...               # cgo                                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘



                              MÉTRICAS
────────────────────────────────────────────────────────────────────────────────

PROMETHEUS (porta 9090)
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  # Pool                                                                     │
│  leeward_workers_total{state="idle|busy|recycling"}                         │
│  leeward_worker_recycles_total                                              │
│                                                                             │
│  # Execuções                                                                │
│  leeward_executions_total                                                   │
│  leeward_executions_failed_total{reason="timeout|oom|error"}                │
│  leeward_execution_duration_seconds{quantile="0.5|0.9|0.99"}                │
│                                                                             │
│  # Recursos                                                                 │
│  leeward_memory_usage_bytes{worker="1|2|3|4"}                               │
│  leeward_cpu_time_seconds_total                                             │
│                                                                             │
│  # Socket                                                                   │
│  leeward_connections_active                                                 │
│  leeward_requests_total                                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘



                             PERFORMANCE
────────────────────────────────────────────────────────────────────────────────

LATÊNCIA BREAKDOWN (warm request, print('hello'))
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  Client serialize         0.05ms                                            │
│  Socket send              0.10ms                                            │
│  Daemon recv + parse      0.10ms                                            │
│  Pool get worker          0.05ms                                            │
│  Pipe send to worker      0.10ms                                            │
│  Worker recv              0.05ms                                            │
│  Mount setup (per-job)    0.50ms                                            │
│  Python exec              1.50ms                                            │
│  Collect stdout           0.10ms                                            │
│  Pipe send result         0.10ms                                            │
│  Daemon serialize         0.05ms                                            │
│  Socket send              0.10ms                                            │
│  Client deserialize       0.05ms                                            │
│  ─────────────────────────────────                                          │
│  TOTAL                    ~3ms                                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


THROUGHPUT
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  4 workers  × 300 req/s/worker  =  ~1,200 req/s                             │
│  8 workers  × 300 req/s/worker  =  ~2,400 req/s                             │
│  16 workers × 300 req/s/worker  =  ~4,800 req/s                             │
│                                                                             │
│  Bottleneck: Python execution time                                          │
│  Com pandas hot: ~50 req/s/worker (processamento real)                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘



                           COMPARAÇÃO FINAL
────────────────────────────────────────────────────────────────────────────────

┌──────────────┬─────────┬─────────┬─────────┬─────────┬─────────────────────┐
│              │  E2B    │ Docker  │  Modal  │  WASM   │  leeward            │
├──────────────┼─────────┼─────────┼─────────┼─────────┼─────────────────────┤
│ Cold start   │  200ms  │  400ms  │  150ms  │   5ms   │  45ms               │
│ Warm request │   50ms  │   80ms  │   30ms  │   1ms   │  3ms                │
│ 2GB file     │  10s+   │   50ms  │  10s+   │   N/A   │  ~0ms (bind mount)  │
│ Throughput   │  500/s  │  100/s  │ 1000/s  │ 5000/s  │  5000/s             │
│ Mem/worker   │   50MB  │  100MB  │   50MB  │   10MB  │  15MB               │
│ Native libs  │    ✓    │    ✓    │    ✓    │    ✗    │  ✓                  │
│ Self-hosted  │    ✗    │    ✓    │    ✗    │    ✓    │  ✓                  │
│ Pricing      │  $$$    │  server │   $$    │  free   │  free               │
└──────────────┴─────────┴─────────┴─────────┴─────────┴─────────────────────┘