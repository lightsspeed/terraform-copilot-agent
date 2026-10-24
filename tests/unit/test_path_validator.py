"""Unit tests for PathValidator."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from terraform_copilot_agent.security.exceptions import (
    PathTraversalError,
    SymlinkEscapeError,
)
from terraform_copilot_agent.security.path_validator import PathValidator


def _can_create_symlinks(tmp_path: Path) -> bool:
    """Check if the current user and OS environment can create symlinks."""
    target = tmp_path / "_probe_target.txt"
    target.write_text("probe")
    link = tmp_path / "_probe_link.txt"
    try:
        os.symlink(target, link)
        return True
    except OSError:
        return False


def test_init_valid_workspace(tmp_path: Path) -> None:
    """Validator initializes successfully with an existing directory."""
    validator = PathValidator(tmp_path)
    assert validator.workspace_root == tmp_path.resolve()


def test_init_invalid_workspace(tmp_path: Path) -> None:
    """Validator rejects non-existent paths or files as workspace roots."""
    non_existent = tmp_path / "does_not_exist"
    with pytest.raises(ValueError, match="does not exist"):
        PathValidator(non_existent)

    file_path = tmp_path / "file.txt"
    file_path.write_text("content")
    with pytest.raises(ValueError, match="must be a directory"):
        PathValidator(file_path)


def test_validate_relative_path_within_workspace(tmp_path: Path) -> None:
    """Relative paths within the workspace resolve safely."""
    validator = PathValidator(tmp_path)
    f = tmp_path / "main.tf"
    f.write_text("resource {}")

    resolved = validator.validate_path("main.tf", must_exist=True)
    assert resolved == f.resolve()


def test_validate_absolute_path_within_workspace(tmp_path: Path) -> None:
    """Absolute paths within the workspace resolve safely."""
    validator = PathValidator(tmp_path)
    f = tmp_path / "nested" / "variables.tf"
    f.parent.mkdir()
    f.write_text("variable {}")

    resolved = validator.validate_path(str(f.resolve()), must_exist=True)
    assert resolved == f.resolve()


def test_validate_absolute_path_outside_workspace(tmp_path: Path) -> None:
    """Absolute paths outside the workspace are rejected with PathTraversalError."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("outside")

    validator = PathValidator(workspace)
    with pytest.raises(PathTraversalError):
        validator.validate_path(str(outside_file.resolve()))


def test_validate_path_traversal_parent_directory(tmp_path: Path) -> None:
    """Parent directory traversal attempts are rejected."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    validator = PathValidator(workspace)
    with pytest.raises(PathTraversalError):
        validator.validate_path("../outside.txt")


def test_validate_nested_path_traversal(tmp_path: Path) -> None:
    """Nested traversal sequences are rejected."""
    workspace = tmp_path / "workspace"
    nested = workspace / "sub" / "deep"
    nested.mkdir(parents=True)

    validator = PathValidator(workspace)
    with pytest.raises(PathTraversalError):
        validator.validate_path("sub/deep/../../../../escape.txt")


def test_validate_prospective_destination_valid(tmp_path: Path) -> None:
    """Prospective non-existent files in workspace are accepted when must_exist=False."""
    validator = PathValidator(tmp_path)
    prospective = "new_infra.tf"

    resolved = validator.validate_path(prospective, must_exist=False)
    assert resolved == (tmp_path / prospective).resolve()
    assert not resolved.exists()


def test_validate_prospective_destination_nested(tmp_path: Path) -> None:
    """Prospective non-existent files in prospective subdirectories are accepted."""
    validator = PathValidator(tmp_path)
    prospective = "modules/networking/main.tf"

    resolved = validator.validate_path(prospective, must_exist=False)
    assert resolved == (tmp_path / prospective).resolve()


def test_validate_prospective_destination_traversal(tmp_path: Path) -> None:
    """Non-existent prospective destinations attempting traversal are rejected."""
    validator = PathValidator(tmp_path)
    with pytest.raises(PathTraversalError):
        validator.validate_path("../prospective.tf", must_exist=False)


def test_validate_must_exist_flag(tmp_path: Path) -> None:
    """must_exist=True raises FileNotFoundError if target does not exist."""
    validator = PathValidator(tmp_path)
    with pytest.raises(FileNotFoundError):
        validator.validate_path("missing.tf", must_exist=True)


def test_symlink_escape_mocked(tmp_path: Path) -> None:
    """Symlink escape is detected and raises SymlinkEscapeError."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    validator = PathValidator(workspace)

    symlink_file = workspace / "link_to_outside.tf"
    outside_target = tmp_path / "outside_target.tf"

    with patch.object(Path, "is_symlink", return_value=True), \
         patch.object(Path, "resolve", return_value=outside_target):
        with pytest.raises(SymlinkEscapeError):
            validator.validate_path(symlink_file)


def test_symlink_escape_real(tmp_path: Path) -> None:
    """Real OS symlink pointing outside workspace raises SymlinkEscapeError."""
    if not _can_create_symlinks(tmp_path):
        pytest.skip("OS environment does not permit creating symlinks (e.g. unprivileged Windows)")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_target = tmp_path / "secret.txt"
    outside_target.write_text("confidential")

    symlink_path = workspace / "escaped_link.txt"
    os.symlink(outside_target, symlink_path)

    validator = PathValidator(workspace)
    with pytest.raises(SymlinkEscapeError):
        validator.validate_path("escaped_link.txt")
