//! ELF binary parsing for shared library resolution.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use goblin::Object;
use memmap2::Mmap;

use crate::error::ProbeError;

use super::ldcache::LdCache;

pub fn resolve_shared_libs(binary: &Path) -> Result<Vec<PathBuf>, ProbeError> {
    let ldcache = LdCache::load()?;
    let mut resolved = HashSet::new();
    let mut result = Vec::new();
    let mut queue = vec![binary.to_path_buf()];

    while let Some(path) = queue.pop() {
        if !resolved.insert(path.clone()) {
            continue;
        }

        let needed = parse_needed(&path)?;
        let (rpath, runpath) = parse_rpath_runpath(&path)?;

        for lib_name in needed {
            if let Some(lib_path) = resolve_library(&lib_name, &path, &rpath, &runpath, &ldcache) {
                if !resolved.contains(&lib_path) {
                    resolved.insert(lib_path.clone());
                    result.push(lib_path.clone());
                    queue.push(lib_path);
                }
            }
        }
    }

    Ok(result)
}

fn parse_needed(path: &Path) -> Result<Vec<String>, ProbeError> {
    let file = std::fs::File::open(path)?;

    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| ProbeError::ElfError {
        path: path.to_path_buf(),
        message: format!("failed to mmap: {e}"),
    })?;

    let object = Object::parse(&mmap).map_err(|e| ProbeError::ElfError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let Object::Elf(elf) = object else {
        return Err(ProbeError::ElfError {
            path: path.to_path_buf(),
            message: "not an ELF binary".to_string(),
        });
    };

    Ok(elf.libraries.iter().map(|s| s.to_string()).collect())
}

fn parse_rpath_runpath(path: &Path) -> Result<(Vec<String>, Vec<String>), ProbeError> {
    let file = std::fs::File::open(path)?;

    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| ProbeError::ElfError {
        path: path.to_path_buf(),
        message: format!("failed to mmap: {e}"),
    })?;

    let object = Object::parse(&mmap).map_err(|e| ProbeError::ElfError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let Object::Elf(elf) = object else {
        return Err(ProbeError::ElfError {
            path: path.to_path_buf(),
            message: "not an ELF binary".to_string(),
        });
    };

    let origin = path.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();

    let expand_path = |s: &str| -> String { s.replace("$ORIGIN", &origin).replace("${ORIGIN}", &origin) };

    let rpath: Vec<String> = elf
        .runpaths
        .iter()
        .filter(|p| !p.is_empty())
        .flat_map(|p| p.split(':'))
        .map(expand_path)
        .collect();

    let runpath = rpath.clone();

    Ok((rpath, runpath))
}

#[allow(dead_code)]
fn parse_interpreter(path: &Path) -> Result<Option<PathBuf>, ProbeError> {
    let file = std::fs::File::open(path)?;

    let mmap = unsafe { Mmap::map(&file) }.map_err(|e| ProbeError::ElfError {
        path: path.to_path_buf(),
        message: format!("failed to mmap: {e}"),
    })?;

    let object = Object::parse(&mmap).map_err(|e| ProbeError::ElfError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    match object {
        Object::Elf(elf) => Ok(elf.interpreter.map(PathBuf::from)),
        _ => Err(ProbeError::ElfError {
            path: path.to_path_buf(),
            message: "not an ELF binary".to_string(),
        }),
    }
}

fn resolve_library(
    name: &str,
    _binary: &Path,
    rpath: &[String],
    runpath: &[String],
    ldcache: &LdCache,
) -> Option<PathBuf> {
    let search_paths = if !runpath.is_empty() { runpath } else { rpath };

    for dir in search_paths {
        let path = Path::new(dir).join(name);
        if path.exists() {
            return Some(path);
        }
    }

    if let Some(path) = ldcache.lookup(name) {
        return Some(path);
    }

    for dir in &["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
        let path = Path::new(dir).join(name);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_elf_binary() -> Option<PathBuf> {
        if let Ok(path) = which::which("ls") {
            return Some(path);
        }
        for path in &["/bin/ls", "/usr/bin/ls"] {
            let p = Path::new(path);
            if p.exists() {
                return Some(p.to_path_buf());
            }
        }
        None
    }

    #[test]
    fn test_parse_needed_dynamic_binary() {
        let Some(binary) = get_elf_binary() else {
            eprintln!("Skipping: No suitable ELF binary found");
            return;
        };

        let result = parse_needed(&binary);
        assert!(result.is_ok(), "Should parse {}", binary.display());

        let libs = result.unwrap();
        if !libs.is_empty() {
            assert!(
                libs.iter().any(|l| l.contains("libc") || l.contains("musl")),
                "Dynamic binary should link libc/musl: {libs:?}"
            );
        }
    }

    #[test]
    fn test_parse_needed_nonexistent() {
        let result = parse_needed(Path::new("/nonexistent/binary"));
        assert!(result.is_err(), "Should fail for nonexistent file");
    }

    #[test]
    fn test_parse_needed_not_elf() {
        let test_files = ["/etc/passwd", "/proc/self/cmdline"];
        for file in test_files {
            if Path::new(file).exists() {
                let result = parse_needed(Path::new(file));
                assert!(result.is_err(), "Should fail for non-ELF file: {file}");
                return;
            }
        }
        eprintln!("Skipping: No suitable non-ELF file found");
    }

    #[test]
    fn test_resolve_shared_libs_dynamic() {
        let Some(binary) = get_elf_binary() else {
            eprintln!("Skipping: No suitable ELF binary found");
            return;
        };

        let result = resolve_shared_libs(&binary);
        assert!(result.is_ok(), "Should resolve {} dependencies", binary.display());

        let libs = result.unwrap();
        for lib in &libs {
            assert!(lib.exists(), "Resolved library should exist: {}", lib.display());
        }
    }

    #[test]
    fn test_parse_rpath_runpath() {
        let Some(binary) = get_elf_binary() else {
            eprintln!("Skipping: No suitable ELF binary found");
            return;
        };

        let result = parse_rpath_runpath(&binary);
        assert!(result.is_ok(), "Should parse RPATH/RUNPATH");
    }

    #[test]
    fn test_parse_interpreter() {
        let Some(binary) = get_elf_binary() else {
            eprintln!("Skipping: No suitable ELF binary found");
            return;
        };

        let result = parse_interpreter(&binary);
        assert!(result.is_ok(), "Should parse interpreter");

        if let Ok(Some(interp)) = result {
            let interp_str = interp.to_string_lossy();
            assert!(
                interp_str.contains("ld-linux") || interp_str.contains("ld.so") || interp_str.contains("ld-musl"),
                "Interpreter should be a dynamic linker: {interp_str}"
            );
        }
    }
}
