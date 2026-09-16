from pathlib import Path


def test_demo_example_stays_in_tree_and_provider_neutral() -> None:
    root = Path(__file__).parents[1]
    readme = (root / "examples/demo-mcp/README.md").read_text()
    server = (root / "examples/demo-mcp/server.py").read_text()
    assert "databricks" not in readme.lower()
    assert "databricks" not in server.lower()
    assert "whoami" in server
    assert not (root / ".gitmodules").exists()
    assert not (root / "examples/databricks-mcp").exists()
