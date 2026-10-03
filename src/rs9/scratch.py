"""Descriptor-relative, exclusive writes into a caller-owned empty directory."""
import json
import os
from pathlib import Path

from rs9.errors import ContractError
from rs9.security import validate_safe_relative_posix_path


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def physical_directory(root):
    path = Path(root).absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ContractError("SYMLINK_REJECTED", "Directory ancestry contains a symlink")
    if not path.is_dir():
        raise ContractError("INVALID_DIRECTORY", "An existing physical directory is required")
    return path


class ConfinedWriter:
    """Never overwrite existing output or follow a directory/link component."""

    def __init__(self, root):
        path = physical_directory(root)
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if os.listdir(self.fd):
            self.close()
            raise ContractError("OUTPUT_NOT_EMPTY", "Output root must be empty")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def write(self, relative, content):
        validate_safe_relative_posix_path(relative)
        if not isinstance(content, bytes):
            raise ContractError("INVALID_TYPE", "Output content must be bytes")
        current = os.dup(self.fd)
        try:
            parts = relative.split("/")
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                os.close(current)
                current = child
            descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o644, dir_fd=current)
            with os.fdopen(descriptor, "wb") as output:
                output.write(content)
        except OSError:
            raise ContractError("OUTPUT_CONFINEMENT", "Confined output write failed") from None
        finally:
            os.close(current)
