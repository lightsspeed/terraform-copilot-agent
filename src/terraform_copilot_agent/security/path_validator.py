"""Path validation and containment security checks."""

import os
from pathlib import Path

from terraform_copilot_agent.security.exceptions import (
    PathTraversalError,
    SymlinkEscapeError,
)


class PathValidator:
    """Validates that filesystem paths remain strictly contained within a designated workspace root."""

    def __init__(self, workspace_root: str | Path) -> None:
        """Initialize the validator with a canonical workspace root.

        Args:
            workspace_root: Path to the isolated workspace directory.

        Raises:
            ValueError: If workspace_root does not exist or is not a directory.
        """
        resolved_root = Path(workspace_root).resolve()
        if not resolved_root.exists():
            raise ValueError(f"Workspace root does not exist: {resolved_root}")
        if not resolved_root.is_dir():
            raise ValueError(f"Workspace root must be a directory: {resolved_root}")

        self._workspace_root = resolved_root

    @property
    def workspace_root(self) -> Path:
        """Return the canonical workspace root path."""
        return self._workspace_root

    def _contains_symlink(self, path: Path) -> bool:
        """Check if the path or any of its existing ancestor components is a symlink."""
        curr = path
        # Walk up until filesystem root
        while curr != curr.parent:
            try:
                if curr.is_symlink():
                    return True
            except OSError:
                pass
            curr = curr.parent
        return False

    def validate_path(self, path: str | Path, must_exist: bool = False) -> Path:
        """Validate and resolve a path against the workspace root.

        Handles relative and absolute paths, directory traversal attempts,
        symlink escapes, and prospective destinations.

        Args:
            path: Relative or absolute path to validate.
            must_exist: If True, the target must already exist on disk.

        Returns:
            Resolved canonical Path safely contained within the workspace root.

        Raises:
            PathTraversalError: If the path attempts to escape the workspace root via ../ or external path.
            SymlinkEscapeError: If the path escapes the workspace root via a symlink.
            FileNotFoundError: If must_exist is True and the file does not exist.
        """
        raw_path = Path(path)

        # Resolve candidate relative to workspace_root if relative, or directly if absolute
        if raw_path.is_absolute():
            candidate = raw_path
        else:
            candidate = self._workspace_root / raw_path

        # Check for symlink in path chain before resolution
        had_symlink = self._contains_symlink(candidate)

        # Canonicalize the path
        resolved = candidate.resolve()

        # Check containment
        is_contained = False
        try:
            is_contained = resolved.is_relative_to(self._workspace_root)
        except AttributeError:
            # Fallback for Python versions where is_relative_to might not be available
            try:
                resolved.relative_to(self._workspace_root)
                is_contained = True
            except ValueError:
                is_contained = False

        # Additional case-folding check on Windows where drive letters or case may vary
        if not is_contained and os.name == "nt":
            try:
                resolved_str = str(resolved).lower()
                root_str = str(self._workspace_root).lower()
                if resolved_str == root_str or resolved_str.startswith(root_str.rstrip("\\") + "\\"):
                    is_contained = True
            except Exception:
                pass

        if not is_contained:
            if had_symlink or candidate.is_symlink():
                raise SymlinkEscapeError(
                    f"Symlink target '{resolved}' escapes workspace root '{self._workspace_root}'"
                )
            raise PathTraversalError(
                f"Path '{path}' resolves to '{resolved}', which is outside workspace root '{self._workspace_root}'"
            )

        # If it's contained, also ensure an existing symlink inside workspace does not escape
        # (covered by resolution check above, but if resolved was inside, verify candidate symlink target)
        if candidate.is_symlink():
            target = candidate.resolve()
            if not target.is_relative_to(self._workspace_root):
                raise SymlinkEscapeError(
                    f"Symlink '{candidate}' points to '{target}' outside workspace root"
                )

        if must_exist and not resolved.exists():
            raise FileNotFoundError(f"Requested file does not exist: {resolved}")

        return resolved
