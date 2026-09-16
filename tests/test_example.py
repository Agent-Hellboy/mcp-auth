from pathlib import Path


def test_optional_example_is_provider_neutral() -> None:
    root = Path(__file__).parents[1]
    readme = (root / "examples/databricks-mcp-integration/README.md").read_text()
    env = (root / "examples/databricks-mcp-integration/.env.example").read_text()
    assert "company" not in readme.lower()
    assert "<owner>" not in env
    assert "DOWNSTREAM_AUDIENCE" in env
    assert (
        "https://github.com/Agent-Hellboy/databrics-mcp.git" in (root / ".gitmodules").read_text()
    )
