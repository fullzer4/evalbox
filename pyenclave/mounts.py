from typing import Any, Dict, List


def build_mount_plan(
    mounts: Dict[str, List[str]],
    stateless: bool = True,
) -> Dict[str, Any]:
    """Build and validate mount plan from user specification.

    Args:
        mounts: Mount specification with 'ro' and 'rw' lists
                Format: ["host_path:container_path", ...]
        stateless: If True, use ephemeral root with no host access

    Returns:
        Normalized mount plan dict ready for sandbox execution

    Note:
        Reserved paths:
            - /inputs: Read-only input data
            - /output: Write output results
            - /state: Persistent state (if not stateless)

        Implementation pending.
    """
    # TODO: Normalize paths
    # TODO: Validate reserved paths (/inputs, /output, /state)
    # TODO: Check for conflicts and overlaps
    # TODO: Verify source paths exist
    return {}


def validate_mounts(plan: Dict[str, Any]) -> None:
    """Validate mount plan for conflicts and security issues.

    Args:
        plan: Mount plan from build_mount_plan()

    Raises:
        MountError: If mount plan has conflicts, invalid paths, or forbidden destinations

    Checks:
        - No path collisions
        - No escaping sandbox root
        - No forbidden system paths
        - Valid source paths exist
    """
    # TODO: Implement validation checks
    pass
