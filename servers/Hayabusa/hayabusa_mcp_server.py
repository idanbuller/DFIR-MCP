#!/usr/bin/env python3
"""
Hayabusa MCP Server

An MCP server that integrates the Yamato-Security Hayabusa CLI, enabling
natural-language driven Windows Event Log forensics: fast timelines, rule-
based detections, and metrics.

This server shells out to a Hayabusa binary. Provide the path via one of:
- Environment variable HAYABUSA_PATH
- Place the binary at servers/Hayabusa/bin/hayabusa (or hayabusa.exe)
- Place the binary under servers/Hayabusa/hayabusa (built from source)

Tools implemented mirror common Hayabusa commands:
- csv_timeline, json_timeline
- eid_metrics, computer_metrics
- list_rules
- detect (alias for csv/json timeline with rules; see command help)
- hayabusa_run (advanced: run arbitrary subcommand and args)

Notes:
- This server does not bundle Hayabusa. Download a release binary from:
  https://github.com/Yamato-Security/hayabusa/releases
- Or build from source following their README, then set HAYABUSA_PATH.
"""

import asyncio
import logging
import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hayabusa-mcp")

# Server configuration
server = Server("hayabusa-mcp")

# Resolve Hayabusa binary path relative to this file or env override
THIS_DIR = Path(__file__).parent
DEFAULT_BIN_DIR = THIS_DIR / "bin"
DEFAULT_BIN_POSIX = DEFAULT_BIN_DIR / "hayabusa"
DEFAULT_BIN_WIN = DEFAULT_BIN_DIR / "hayabusa.exe"


def _find_hayabusa_binary() -> Optional[Path]:
    # 1) Env override
    env_path = os.environ.get("HAYABUSA_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists() and p.is_file():
            return p
    # 2) Default bin folder
    candidates = [DEFAULT_BIN_POSIX, DEFAULT_BIN_WIN]
    # 3) If user built under servers/Hayabusa/hayabusa (repo dir), search for binary
    repo_dir = THIS_DIR / "hayabusa"
    if platform.system().lower().startswith("win"):
        candidates.append(repo_dir / "hayabusa.exe")
    else:
        candidates.append(repo_dir / "hayabusa")
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None


async def _run_hayabusa(args: Sequence[str], cwd: Optional[Path] = None) -> Dict[str, Any]:
    bin_path = _find_hayabusa_binary()
    if not bin_path:
        raise FileNotFoundError(
            "Hayabusa binary not found. Set HAYABUSA_PATH or place the binary at servers/Hayabusa/bin/."
        )

    cmd = [str(bin_path), *args]
    logger.info("Running Hayabusa: %s", " ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
    )
    stdout, stderr = await proc.communicate()

    return {
        "returncode": proc.returncode,
        "stdout": stdout.decode(errors="ignore"),
        "stderr": stderr.decode(errors="ignore"),
        "command": cmd,
    }


@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    return [
        types.Tool(
            name="csv_timeline",
            description="Generate CSV timeline from EVTX folder using Hayabusa.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_dir": {"type": "string", "description": "Path to folder containing .evtx files"},
                    "output": {"type": "string", "description": "Output CSV file path (optional)"},
                    "rules": {"type": "string", "description": "Rules directory or zip (optional)"},
                    "use_utc": {"type": "boolean", "description": "Set to true to output timestamps in UTC (default: local time)"},
                    "language": {"type": "string", "description": "Language code like en-US/ja-JP (optional)"},
                    "overwrite": {"type": "boolean", "description": "Set to true to overwrite the output file if it exists."},

                    "extra_args": {"type": "array", "items": {"type": "string"}, "description": "Advanced extra CLI args"}
                },
                "required": ["evtx_dir"]
            }
        ),
        types.Tool(
            name="json_timeline",
            description="Generate JSON timeline from EVTX folder using Hayabusa.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_dir": {"type": "string"},
                    "output": {"type": "string", "description": "Output JSON file path (optional)"},
                    "rules": {"type": "string", "description": "Rules directory or zip (optional)"},
                    "use_utc": {"type": "boolean", "description": "Set to true to output timestamps in UTC (default: local time)"},
                    "language": {"type": "string"},
                    "extra_args": {"type": "array", "items": {"type": "string"}},
                    "overwrite": {"type": "boolean", "description": "Set to true to overwrite the output file if it exists."}
                },
                "required": ["evtx_dir"]
            }
        ),
        types.Tool(
            name="eid_metrics",
            description="Compute event ID metrics (counts/percentages per channel).",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_dir": {"type": "string"},
                    "output": {"type": "string", "description": "Output CSV path (optional)"},
                    "extra_args": {"type": "array", "items": {"type": "string"}},
                    "overwrite": {"type": "boolean", "description": "Set to true to overwrite the output file if it exists."}
                },
                "required": ["evtx_dir"]
            }
        ),
        types.Tool(
            name="computer_metrics",
            description="Compute computer metrics and export as CSV.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_dir": {"type": "string"},
                    "output": {"type": "string", "description": "Output CSV path (optional)"},
                    "extra_args": {"type": "array", "items": {"type": "string"}},
                    "overwrite": {"type": "boolean", "description": "Set to true to overwrite the output file if it exists."}
                },
                "required": ["evtx_dir"]
            }
        ),
        types.Tool(
            name="hayabusa_run",
            description="Advanced: run an arbitrary Hayabusa subcommand with args.",
            inputSchema={
                "type": "object",
                "properties": {
                    "subcommand": {"type": "string", "description": "e.g., csv-timeline, json-timeline, eid-metrics"},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "Raw CLI args list"}
                },
                "required": ["subcommand"]
            }
        ),
        types.Tool(
            name="hayabusa_version",
            description="Print Hayabusa help and environment info. A good way to check if the binary is working.",
            inputSchema={"type": "object", "properties": {}, "additionalProperties": False}
        ),
        types.Tool(
            name="run_and_upload_to_timesketch",
            description="Run Hayabusa and upload the resulting timeline to Timesketch.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_dir": {"type": "string", "description": "Path to folder containing .evtx files"},
                    "sketch_id": {"type": "integer", "description": "Timesketch sketch ID to upload to"},
                    "timeline_name": {"type": "string", "description": "Name for the new timeline in Timesketch"},
                    "rules": {"type": "string", "description": "Rules directory or zip (optional)"},
                    "use_utc": {"type": "boolean", "description": "Set to true to output timestamps in UTC (default: local time)"},
                },
                "required": ["evtx_dir", "sketch_id", "timeline_name"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[types.TextContent]:
    try:
        if name == "csv_timeline":
            return await _tool_csv_timeline(arguments)
        if name == "json_timeline":
            return await _tool_json_timeline(arguments)
        if name == "eid_metrics":
            return await _tool_eid_metrics(arguments)
        if name == "computer_metrics":
            return await _tool_computer_metrics(arguments)
        if name == "hayabusa_run":
            return await _tool_hayabusa_run(arguments)
        if name == "hayabusa_version":
            return await _tool_hayabusa_version()
        if name == "run_and_upload_to_timesketch":
            return await _tool_run_and_upload(arguments)
        raise ValueError(f"Unknown tool: {name}")
    except Exception as e:
        logger.exception("Error in tool %s", name)
        return [types.TextContent(type="text", text=f"Error: {e}")]


def _common_args_for_timeline(arguments: Dict[str, Any], json_mode: bool) -> List[str]:
    evtx_dir = arguments["evtx_dir"]
    output = arguments.get("output")
    rules = arguments.get("rules")
    use_utc = arguments.get("use_utc", False)
    language = arguments.get("language")
    overwrite = arguments.get("overwrite", False)
    extra = arguments.get("extra_args", []) or []

    sub = "json-timeline" if json_mode else "csv-timeline"
    args: List[str] = [sub, "-d", evtx_dir]
    if output:
        args += ["-o", output]
    if overwrite:
        args.append("-C")
    if rules:
        args += ["-r", rules]
    if use_utc:
        args.append("-U")
    if language:
        args += ["--language", language]
    # By default, disable scan wizard for automation
    args += ["--no-wizard"]
    # Typical sensible defaults
    # args += ["--merge", "--sort"]  # Uncomment if desired
    if extra:
        args += list(map(str, extra))
    return args


async def _tool_csv_timeline(arguments: Dict[str, Any]) -> List[types.TextContent]:
    result = await _run_hayabusa(_common_args_for_timeline(arguments, json_mode=False))
    return _format_result(result)


async def _tool_json_timeline(arguments: Dict[str, Any]) -> List[types.TextContent]:
    result = await _run_hayabusa(_common_args_for_timeline(arguments, json_mode=True))
    return _format_result(result)


async def _tool_eid_metrics(arguments: Dict[str, Any]) -> List[types.TextContent]:
    evtx_dir = arguments["evtx_dir"]
    output = arguments.get("output")
    overwrite = arguments.get("overwrite", False)
    extra = arguments.get("extra_args", []) or []
    args: List[str] = ["eid-metrics", "-d", evtx_dir]
    if output:
        args += ["-o", output]
    if overwrite:
        args.append("-C")
    if extra:
        args += list(map(str, extra))
    result = await _run_hayabusa(args)
    return _format_result(result)


async def _tool_computer_metrics(arguments: Dict[str, Any]) -> List[types.TextContent]:
    evtx_dir = arguments["evtx_dir"]
    output = arguments.get("output")
    overwrite = arguments.get("overwrite", False)
    extra = arguments.get("extra_args", []) or []
    args: List[str] = ["computer-metrics", "-d", evtx_dir]
    if output:
        args += ["-o", output]
    if overwrite:
        args.append("-C")
    if extra:
        args += list(map(str, extra))
    result = await _run_hayabusa(args)
    return _format_result(result)




async def _tool_hayabusa_run(arguments: Dict[str, Any]) -> List[types.TextContent]:
    sub = arguments["subcommand"]
    raw_args = arguments.get("args", []) or []
    args = [sub, *[str(a) for a in raw_args]]
    result = await _run_hayabusa(args)
    return _format_result(result)


async def _tool_hayabusa_version() -> List[types.TextContent]:
    # Using 'help' is a reliable way to check if the binary is executable
    # and it often contains the version number in its output.
    result = await _run_hayabusa(["help"])
    return _format_result(result)


async def _tool_run_and_upload(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """Runs Hayabusa and uploads the timeline to Timesketch."""
    evtx_dir = arguments["evtx_dir"]
    sketch_id = arguments["sketch_id"]
    timeline_name = arguments["timeline_name"]

    # Define the output path for the timeline CSV
    output_dir = Path(evtx_dir).parent
    output_file = output_dir / f"{timeline_name}.csv"

    # Construct the arguments for the Hayabusa csv_timeline tool
    hayabusa_args = {
        "evtx_dir": evtx_dir,
        "output": str(output_file),
        "overwrite": True,  # Always overwrite to ensure fresh data
        "use_utc": arguments.get("use_utc", True), # Default to UTC for consistency
        "rules": arguments.get("rules"),
    }

    # Run the Hayabusa timeline generation
    logger.info(f"Generating Hayabusa timeline: {output_file}")
    timeline_result = await _tool_csv_timeline(hayabusa_args)

    # Check if the timeline was created successfully
    if not output_file.exists():
        return [
            types.TextContent(
                type="text",
                text=f"Hayabusa timeline generation failed. See logs for details. Result: {timeline_result[0].text}",
            )
        ]

    logger.info("Timeline created successfully. Now uploading to Timesketch...")

    # Construct the arguments for the Timesketch upload_timeline tool
    timesketch_args = {
        "sketch_id": sketch_id,
        "file_path": str(output_file),
        "timeline_name": timeline_name,
    }

    # Call the Timesketch MCP server
    try:
        upload_result = await server.call_tool_by_name(
            "timesketch-mcp", "upload_timeline", timesketch_args
        )
        return upload_result
    except Exception as e:
        logger.exception("Failed to call Timesketch server.")
        return [types.TextContent(type="text", text=f"Error uploading to Timesketch: {e}")]


def _format_result(result: Dict[str, Any]) -> List[types.TextContent]:
    rc = result.get("returncode", 1)
    stdout = result.get("stdout", "").strip()
    stderr = result.get("stderr", "").strip()

    if rc == 0:
        if stdout:
            return [types.TextContent(type="text", text=stdout)]
        else:
            return [types.TextContent(type="text", text="Success (no stdout).")]
    else:
        msg = stderr or stdout or "Unknown error"
        return [types.TextContent(type="text", text=f"Hayabusa command failed (rc={rc}):\n{msg}")]


class DuckOptions:
    def __init__(self):
        self.capabilities = {}
        self.server_name = "hayabusa-mcp"
        self.server_version = "0.0.1"
        self.tools_changed = True
        self.resources_changed = False
        self.instructions = ""

async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, DuckOptions())


if __name__ == "__main__":
    asyncio.run(main())
