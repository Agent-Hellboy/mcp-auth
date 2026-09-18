import subprocess
from pathlib import Path


def _tracked_paths(root: Path) -> set[str] | None:
    """Paths this repository actually tracks, or None when git cannot answer."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return set(result.stdout.split())


def test_demo_example_stays_in_tree_and_provider_neutral() -> None:
    root = Path(__file__).parents[1]
    readme = (root / "examples/demo-mcp/README.md").read_text()
    server = (root / "examples/demo-mcp/server.py").read_text()
    assert "databricks" not in readme.lower()
    assert "databricks" not in server.lower()
    assert "whoami" in server


def test_repository_ships_no_provider_specific_example() -> None:
    """The example that ships must stay provider-neutral.

    This checks what the repository *tracks*, not what happens to sit in the
    working tree: a contributor who clones an unrelated project into examples/
    is not shipping it, and should not fail the suite for it. .gitignore keeps
    that from being committed by accident, and this asserts the outcome.
    """
    root = Path(__file__).parents[1]
    tracked = _tracked_paths(root)
    if tracked is None:
        # Not a git checkout (an sdist, say). Fall back to the filesystem.
        assert not (root / ".gitmodules").exists()
        assert not (root / "examples/databricks-mcp").exists()
        return

    assert ".gitmodules" not in tracked
    offending = sorted(path for path in tracked if path.startswith("examples/databricks-mcp"))
    assert offending == [], f"provider-specific example is tracked: {offending}"
