import shutil
import sys

import pytest

LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="Linux-only")
HAS_ISOLATE = shutil.which("isolate") is not None
ISOLATE_ONLY = pytest.mark.skipif(not HAS_ISOLATE, reason="requires 'isolate' installed")
