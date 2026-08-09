# Tool Integration Guide

This project now supports dynamic tool integration from external projects.

## What Was Added

- Dynamic tool discovery in `tools/tool_factory.py`
- Built-in plugin directory: `tools/plugins/`
- External plugin directory support via env var: `REDAGENT_TOOL_PLUGIN_PATHS`
- Auto-detection for sibling projects: `../woodpecker-main` and `../BSF-master`
- Reasoning tool whitelist is now generated from the live tool registry

## Plugin Contract

A plugin is a Python file with a `register_tools()` function that returns either:

1. `dict[str, BaseTool]`
2. `list[BaseTool]`

Each tool must inherit from `BaseTool` and implement `execute(params)`.

## External Toolpack Integration Steps

1. Extract each external project locally.
2. Create adapter plugin files that wrap their tools into `BaseTool` classes.
3. Set plugin paths:

```powershell
$env:REDAGENT_TOOL_PLUGIN_PATHS = "C:\path\to\toolpack1;C:\path\to\toolpack2"
```

4. Start your app normally.

The `ToolFactory` will auto-load built-in and external plugins at startup.

## Combining Provided Projects Directly

If you extract your provided archives to the workspace root as:

- `woodpecker-main/`
- `BSF-master/`

then Red Agent will automatically scan these plugin folders:

- `woodpecker-main/red_agent/tools/plugins/`
- `woodpecker-main/tools/plugins/`
- `woodpecker-main/plugins/`
- `BSF-master/red_agent/tools/plugins/`
- `BSF-master/tools/plugins/`
- `BSF-master/plugins/`

No extra code changes are needed once those folders exist.

## Included Built-in Plugin

- `tools/plugins/nuclei_plugin.py`: registers `nuclei` scanner tool.
- `tools/plugins/woodpecker_project_plugin.py`: registers `woodpecker_experiments`, `woodpecker_snippet`, `woodpecker_verify`.
- `tools/plugins/bsf_project_plugin.py`: registers `bsf_simulation_overview`, `bsf_graph_summary`.

## Important Notes

- Only add tools from trusted source code.
- Keep plugins non-interactive and deterministic.
- Return structured output (`stdout`, `stderr`, `status`, `return_code`) for robust orchestration.

## Current Combined Project Status

With your extracted folders in workspace root:

- `woodpecker-main/`
- `BSF-master/`

the above adapters are loaded automatically by `ToolFactory` and exposed to reasoning without hardcoded changes.
