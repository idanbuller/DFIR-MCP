#!/usr/bin/env python3
"""
Chainsaw MCP Server

An MCP server that integrates the Chainsaw tool for detecting threats in event logs
using Sigma rules. It allows AI assistants to scan files and directories for
malicious patterns through the Model Context Protocol.
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("chainsaw-mcp")

# Server configuration
server = Server("chainsaw-mcp")

# Path to the Chainsaw executable (relative to this file)
CHAINSAW_PATH = Path(__file__).parent / "bin" / "chainsaw"
# Path to the Sigma rules directory
SIGMA_RULES_PATH = Path(__file__).parent / "chainsaw" / "rules"


@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """
    List available tools for Chainsaw analysis.
    """
    return [
        types.Tool(
            name="run_chainsaw_scan",
            description="Run a Chainsaw hunt on a file or directory of event logs using Sigma rules",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Path to the event log file or directory to scan"
                    },
                    "rules_path": {
                        "type": "string",
                        "description": f"Optional: Path to a custom Sigma rules directory. Defaults to the built-in rules."
                    },
                    "level": {
                        "type": "string",
                        "enum": ["informational", "low", "medium", "high", "critical"],
                        "default": "high",
                        "description": "Minimum detection level to report"
                    },
                    "from_timestamp": {
                        "type": "string",
                        "description": "The timestamp to search from (e.g., '2023-01-01T12:00:00')"
                    },
                    "to_timestamp": {
                        "type": "string",
                        "description": "The timestamp to search up to (e.g., '2023-01-01T13:00:00')"
                    }
                },
                "required": ["target_path"]
            }
        ),
        types.Tool(
            name="search_chainsaw_logs",
            description="Search logs for a specific pattern, regex, or Tau expression",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Path to the event log file or directory to search"
                    },
                    "pattern": {
                        "type": "string",
                        "description": "A string pattern to search for"
                    },
                    "regex": {
                        "type": "string",
                        "description": "A regular expression to search for"
                    },
                    "tau_expression": {
                        "type": "string",
                        "description": "A Tau expression to filter logs (e.g., 'Event.System.EventID: =4104')"
                    },
                    "from_timestamp": {
                        "type": "string",
                        "description": "The timestamp to search from"
                    },
                    "to_timestamp": {
                        "type": "string",
                        "description": "The timestamp to search up to"
                    }
                },
                "required": ["target_path"]
            }
        ),
        types.Tool(
            name="dump_artifact",
            description="Dump data from an artifact file in JSON or JSONL format",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Path to the artifact file to dump"
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["json", "jsonl"],
                        "default": "jsonl",
                        "description": "The output format for the dumped data"
                    }
                },
                "required": ["target_path"]
            }
        ),
        types.Tool(
            name="list_sigma_rules",
            description="List available Sigma rule sets in the repository",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: Dict[str, Any]
) -> List[types.TextContent]:
    """
    Handle tool calls for Chainsaw analysis.
    """
    try:
        if name == "run_chainsaw_scan":
            return await run_chainsaw_scan(arguments)
        elif name == "search_chainsaw_logs":
            return await search_chainsaw_logs(arguments)
        elif name == "dump_artifact":
            return await dump_artifact(arguments)
        elif name == "list_sigma_rules":
            return await list_sigma_rules(arguments)
        else:
            raise ValueError(f"Unknown tool: {name}")
    except Exception as e:
        logger.error(f"Error in tool {name}: {str(e)}")
        return [types.TextContent(type="text", text=f"Error: {str(e)}")]


async def run_chainsaw_scan(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """
    Run a Chainsaw 'hunt' on a file or directory.
    """
    target_path = arguments["target_path"]
    rules_path = arguments.get("rules_path", str(SIGMA_RULES_PATH))
    level = arguments.get("level", "high")
    from_timestamp = arguments.get("from_timestamp")
    to_timestamp = arguments.get("to_timestamp")

    if not os.path.exists(target_path):
        return [types.TextContent(type="text", text=f"Error: Target path not found: {target_path}")]

    if not CHAINSAW_PATH.exists():
        return [types.TextContent(type="text", text=f"Error: Chainsaw executable not found at {CHAINSAW_PATH}. Please place it in the 'servers/Chainsaw/bin' directory.")]

    with tempfile.TemporaryDirectory() as temp_dir:
        output_file = Path(temp_dir) / "chainsaw_results.jsonl"

        try:
            command = [
                str(CHAINSAW_PATH),
                "hunt",
                target_path,
                "-s", rules_path,
                "--json",
                "-o", str(output_file),
                "--level", level
            ]

            if from_timestamp:
                command.extend(["--from", from_timestamp])
            if to_timestamp:
                command.extend(["--to", to_timestamp])

            logger.info(f"Running Chainsaw command: {' '.join(command)}")
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                err = (stderr.decode(errors='ignore') if stderr else '').strip()
                return [types.TextContent(type="text", text=f"Chainsaw scan failed: {err}")]

            if not output_file.exists():
                return [types.TextContent(type="text", text="Error: Chainsaw produced no output file.")]

            with open(output_file, 'r', encoding='utf-8') as f:
                results_content = f.read()

            # Return the full JSON content directly
            return [types.TextContent(
                type="text",
                text=f"Chainsaw scan completed successfully!\n\n{results_content}"
            )]

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error during Chainsaw scan: {str(e)}")]


async def list_sigma_rules(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """
    List the available Sigma rule directories.
    """
    if not SIGMA_RULES_PATH.exists() or not SIGMA_RULES_PATH.is_dir():
        return [types.TextContent(type="text", text=f"Sigma rules directory not found at {SIGMA_RULES_PATH}")]

    rule_dirs = [d.name for d in SIGMA_RULES_PATH.iterdir() if d.is_dir()]

    if not rule_dirs:
        return [types.TextContent(type="text", text="No Sigma rule directories found.")]

    return [types.TextContent(type="text", text="Available Sigma rule sets:\n- " + "\n- ".join(rule_dirs))]

async def search_chainsaw_logs(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """
    Run a Chainsaw 'search' on a file or directory.
    """
    target_path = arguments["target_path"]
    pattern = arguments.get("pattern")
    regex = arguments.get("regex")
    tau_expression = arguments.get("tau_expression")
    from_timestamp = arguments.get("from_timestamp")
    to_timestamp = arguments.get("to_timestamp")

    if not any([pattern, regex, tau_expression]):
        return [types.TextContent(type="text", text="Error: You must provide a 'pattern', 'regex', or 'tau_expression' to search for.")]

    if not os.path.exists(target_path):
        return [types.TextContent(type="text", text=f"Error: Target path not found: {target_path}")]

    if not CHAINSAW_PATH.exists():
        return [types.TextContent(type="text", text=f"Error: Chainsaw executable not found at {CHAINSAW_PATH}.")]

    with tempfile.TemporaryDirectory() as temp_dir:
        output_file = Path(temp_dir) / "chainsaw_search_results.jsonl"

        try:
            command = [
                str(CHAINSAW_PATH),
                "search",
                target_path,
                "--json",
                "-o", str(output_file)
            ]

            if pattern:
                command.append(pattern)
            if regex:
                command.extend(["-e", regex])
            if tau_expression:
                command.extend(["-t", tau_expression])
            if from_timestamp:
                command.extend(["--from", from_timestamp])
            if to_timestamp:
                command.extend(["--to", to_timestamp])

            logger.info(f"Running Chainsaw command: {' '.join(command)}")
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                err = (stderr.decode(errors='ignore') if stderr else '').strip()
                return [types.TextContent(type="text", text=f"Chainsaw search failed: {err}")]

            if not output_file.exists():
                return [types.TextContent(type="text", text="Error: Chainsaw produced no output file.")]

            with open(output_file, 'r', encoding='utf-8') as f:
                results_content = f.read()

            # Return the full JSON content directly
            return [types.TextContent(
                type="text",
                text=f"Chainsaw search completed successfully!\n\n{results_content}"
            )]

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error during Chainsaw search: {str(e)}")]


async def dump_artifact(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """
    Run a Chainsaw 'dump' on an artifact file.
    """
    target_path = arguments["target_path"]
    output_format = arguments.get("output_format", "jsonl")

    if not os.path.exists(target_path):
        return [types.TextContent(type="text", text=f"Error: Target path not found: {target_path}")]

    if not CHAINSAW_PATH.exists():
        return [types.TextContent(type="text", text=f"Error: Chainsaw executable not found at {CHAINSAW_PATH}.")]

    with tempfile.TemporaryDirectory() as temp_dir:
        output_file = Path(temp_dir) / f"chainsaw_dump.{output_format}"

        try:
            command = [
                str(CHAINSAW_PATH),
                "dump",
                target_path,
                "-o", str(output_file)
            ]

            if output_format == "json":
                command.append("--json")
            else:
                command.append("--jsonl")

            logger.info(f"Running Chainsaw command: {' '.join(command)}")
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                err = (stderr.decode(errors='ignore') if stderr else '').strip()
                return [types.TextContent(type="text", text=f"Chainsaw dump failed: {err}")]

            if not output_file.exists():
                return [types.TextContent(type="text", text="Error: Chainsaw produced no output file.")]

            with open(output_file, 'r', encoding='utf-8') as f:
                dump_content = f.read()
            
            # Return the full content of the dumped file
            return [types.TextContent(type="text", text=f"Chainsaw dump completed successfully!\n\n{dump_content}")]

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error during Chainsaw dump: {str(e)}")]

async def main():
    """
    Main entry point for the MCP server.
    """
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            NotificationOptions(
                tools_changed=True
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
