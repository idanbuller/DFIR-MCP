#!/usr/bin/env python3
"""
Plaso MCP Server

An MCP server that integrates the Plaso timeline analysis tool, allowing AI
assistants to process forensic artifacts and timelines from storage media.
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Any, Dict, List

import mcp.server.stdio
import mcp.types as types
from mcp.server import Server

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("plaso-mcp")

# Server configuration
server = Server("plaso-mcp")

# Path to the Plaso tools (relative to this file)
PLASO_DIR = Path(__file__).parent
LOG2TIMELINE_PATH = PLASO_DIR / "plaso" / "scripts" / "log2timeline.py"
PSORT_PATH = PLASO_DIR / "plaso" / "scripts" / "psort.py"

@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """
    List available tools for Plaso-based forensic analysis.
    """
    return [
        types.Tool(
            name="create_timeline",
            description="Run log2timeline to create a .plaso storage file from a source.",
            inputSchema={
                "type": "object",
                "properties": {
                    "source_path": {
                        "type": "string",
                        "description": "Path to the source file or directory to analyze."
                    },
                    "storage_file": {
                        "type": "string",
                        "description": "Path to save the output .plaso storage file."
                    },
                    "artifact_definitions": {
                        "type": "string",
                        "description": "Optional path to a directory with custom artifact definitions."
                    }
                },
                "required": ["source_path", "storage_file"]
            }
        ),
        types.Tool(
            name="export_timeline",
            description="Run psort to convert a .plaso file to a readable format (e.g., CSV), with optional filtering.",
            inputSchema={
                "type": "object",
                "properties": {
                    "plaso_file": {
                        "type": "string",
                        "description": "Path to the .plaso storage file to export."
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Path to save the exported output file (e.g., 'timeline.csv')."
                    },
                    "output_format": {
                        "type": "string",
                        "default": "l2tcsv",
                        "description": "Output format for psort (e.g., 'l2tcsv', 'json', 'json_line')."
                    },
                    "filter_query": {
                        "type": "string",
                        "description": "Optional filter query to apply, e.g., \"date > '2025-08-20' AND date < '2025-08-26'\"."
                    }
                },
                "required": ["plaso_file", "output_file"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: Dict[str, Any]
) -> List[types.TextContent]:
    """
    Handle tool calls for Plaso forensic analysis.
    """
    try:
        if name == "create_timeline":
            return await create_timeline(arguments)
        elif name == "export_timeline":
            return await export_timeline(arguments)
        else:
            raise ValueError(f"Unknown tool: {name}")
    except Exception as e:
        logger.error(f"Error in tool {name}: {str(e)}")
        return [types.TextContent(type="text", text=f"Error: {str(e)}")]

async def create_timeline(arguments: Dict[str, Any]) -> List[types.TextContent]:
    source_path = arguments["source_path"]
    storage_file = arguments["storage_file"]
    artifact_definitions = arguments.get("artifact_definitions")

    if not os.path.exists(source_path):
        return [types.TextContent(type="text", text=f"Error: Source path not found: {source_path}")]
    if not LOG2TIMELINE_PATH.exists():
        return [types.TextContent(type="text", text=f"Error: log2timeline.py not found at {LOG2TIMELINE_PATH}")]

    command = [sys.executable, str(LOG2TIMELINE_PATH), "--storage_file", storage_file, source_path]
    if artifact_definitions:
        if not os.path.exists(artifact_definitions):
            return [types.TextContent(type="text", text=f"Error: Artifact definitions path not found: {artifact_definitions}")]
        command.extend(["--artifact_definitions", artifact_definitions])

    # Add the Plaso project root to the Python path
    env = os.environ.copy()
    plaso_root = str(PLASO_DIR)
    env['PYTHONPATH'] = f"{plaso_root}{os.pathsep}{env.get('PYTHONPATH', '')}"

    logger.info(f"Running log2timeline command: {' '.join(command)}")
    process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
    
    stdout, stderr = await process.communicate()
    out_text = (stdout.decode(errors='ignore') if stdout else '').strip()
    err_text = (stderr.decode(errors='ignore') if stderr else '').strip()

    response = f"""### Terminal Output (log2timeline.py)

**STDOUT:**
```
{out_text}
```

**STDERR:**
```
{err_text}
```

--- 
"""

    if process.returncode != 0:
        response += "**Result:** `log2timeline.py` failed."
        return [types.TextContent(type="text", text=response)]

    if os.path.exists(storage_file):
        response += f"**Result:** Timeline created successfully at `{storage_file}`"
    else:
        response += "**Result:** `log2timeline.py` ran, but the storage file was not created."
    
    return [types.TextContent(type="text", text=response)]

async def export_timeline(arguments: Dict[str, Any]) -> List[types.TextContent]:
    plaso_file = arguments["plaso_file"]
    output_file = arguments["output_file"]
    output_format = arguments.get("output_format", "l2tcsv")
    filter_query = arguments.get("filter_query")

    if not os.path.exists(plaso_file):
        return [types.TextContent(type="text", text=f"Error: Plaso file not found: {plaso_file}")]
    if not PSORT_PATH.exists():
        return [types.TextContent(type="text", text=f"Error: psort.py not found at {PSORT_PATH}")]

    command = [sys.executable, str(PSORT_PATH), "-o", output_format, "-w", output_file, plaso_file]
    if filter_query:
        command.append(filter_query)

    # Add the Plaso project root to the Python path
    env = os.environ.copy()
    plaso_root = str(PLASO_DIR)
    env['PYTHONPATH'] = f"{plaso_root}{os.pathsep}{env.get('PYTHONPATH', '')}"

    logger.info(f"Running psort command: {' '.join(command)}")
    process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
    
    stdout, stderr = await process.communicate()
    out_text = (stdout.decode(errors='ignore') if stdout else '').strip()
    err_text = (stderr.decode(errors='ignore') if stderr else '').strip()

    response = f"""### Terminal Output (psort.py)

**STDOUT:**
```
{out_text}
```

**STDERR:**
```
{err_text}
```

--- 
"""

    if process.returncode != 0:
        response += "**Result:** `psort.py` failed."
        return [types.TextContent(type="text", text=response)]

    if os.path.exists(output_file):
        response += f"**Result:** Timeline exported successfully to `{output_file}`"
    else:
        response += "**Result:** `psort.py` ran, but the output file was not created."

    return [types.TextContent(type="text", text=response)]

class DuckOptions:
    def __init__(self):
        self.capabilities = {}
        self.server_name = "plaso-mcp"
        self.server_version = "0.0.1"
        self.tools_changed = True
        self.resources_changed = True
        self.instructions = ""

async def main():
    """
    Main entry point for the MCP server.
    """
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, DuckOptions())

if __name__ == "__main__":
    asyncio.run(main())
