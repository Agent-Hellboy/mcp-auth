# Examples

The provider-specific MCP example is an optional Git submodule at
`examples/databricks-mcp`. Initialize it only when you want to inspect or run
that example:

```bash
git submodule update --init --recursive
```

The provider-neutral configuration fixture in
`examples/databricks-mcp-integration/` documents the boundary between the
reusable SDK and an application-specific MCP server. It is intentionally
usable without the submodule.
