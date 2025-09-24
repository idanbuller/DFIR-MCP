#!/usr/bin/env python3
"""
Hindsight MCP Server

An MCP server that integrates the Hindsight browser forensics tool,
allowing AI assistants to analyze browser history files and extract
forensic artifacts through the Model Context Protocol.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hindsight-mcp")

# Server configuration
server = Server("hindsight-mcp")

# Path to the Hindsight CLI script (relative to this file)
# Note: In this project, Hindsight lives under `hindsight/hindsight.py`
HINDSIGHT_PATH = Path(__file__).parent / "hindsight" / "hindsight.py"

# Storage for analysis results
analysis_results: Dict[str, Dict[str, Any]] = {}


@server.list_tools()
async def handle_list_tools() -> List[types.Tool]:
    """
    List available tools for browser forensics analysis.
    """
    return [
        types.Tool(
            name="analyze_browser_history",
            description="Analyze a browser history file using Hindsight forensics tool",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the browser history file (e.g., Chrome 'History', Firefox 'places.sqlite')"
                    },
                    "browser_type": {
                        "type": "string",
                        "enum": ["Chrome", "Brave"],
                        "default": "Chrome",
                        "description": "Type of browser the history file belongs to"
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["jsonl", "xlsx", "sqlite"],
                        "default": "jsonl",
                        "description": "Output format for the analysis results"
                    }
                },
                "required": ["file_path"]
            }
        ),
        types.Tool(
            name="list_analyses",
            description="List stored analysis sessions and their metadata (IDs, sources, timestamps)",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        types.Tool(
            name="analyze_chrome_profile",
            description="Analyze an entire Chrome profile directory for comprehensive forensics",
            inputSchema={
                "type": "object",
                "properties": {
                    "profile_path": {
                        "type": "string",
                        "description": "Path to the Chrome profile directory (usually contains 'Default' folder)"
                    },
                    "cache_path": {
                        "type": "string",
                        "description": "Optional: Path to cache directory if separate from profile"
                    },
                    "browser_type": {
                        "type": "string",
                        "enum": ["Chrome", "Brave"],
                        "default": "Chrome",
                        "description": "Type of Chromium-based browser"
                    }
                },
                "required": ["profile_path"]
            }
        ),
        types.Tool(
            name="search_analysis_results",
            description="Search through previous analysis results for specific patterns or data",
            inputSchema={
                "type": "object",
                "properties": {
                    "analysis_id": {
                        "type": "string",
                        "description": "ID of the analysis to search through"
                    },
                    "search_term": {
                        "type": "string",
                        "description": "Term to search for in URLs, titles, or other text fields"
                    },
                    "artifact_type": {
                        "type": "string",
                        "enum": ["urls", "downloads", "cookies", "bookmarks", "autofill", "extensions", "cache"],
                        "description": "Optional: Limit search to specific artifact type"
                    },
                    "date_range": {
                        "type": "object",
                        "properties": {
                            "start_date": {"type": "string", "format": "date"},
                            "end_date": {"type": "string", "format": "date"}
                        },
                        "description": "Optional: Filter results by date range"
                    }
                },
                "required": ["analysis_id", "search_term"]
            }
        ),
        types.Tool(
            name="get_analysis_summary",
            description="Get a summary of analysis results including statistics and key findings",
            inputSchema={
                "type": "object",
                "properties": {
                    "analysis_id": {
                        "type": "string",
                        "description": "ID of the analysis to summarize"
                    }
                },
                "required": ["analysis_id"]
            }
        )
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: Dict[str, Any]
) -> List[types.TextContent]:
    """
    Handle tool calls for browser forensics analysis.
    """
    try:
        if name == "analyze_browser_history":
            return await analyze_browser_history(arguments)
        elif name == "analyze_chrome_profile":
            return await analyze_chrome_profile(arguments)
        elif name == "search_analysis_results":
            return await search_analysis_results(arguments)
        elif name == "get_analysis_summary":
            return await get_analysis_summary(arguments)
        elif name == "list_analyses":
            return await list_analyses(arguments)
        else:
            raise ValueError(f"Unknown tool: {name}")
    except Exception as e:
        logger.error(f"Error in tool {name}: {str(e)}")
        return [types.TextContent(type="text", text=f"Error: {str(e)}")]


async def analyze_browser_history(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """
    Analyze a single browser history file using Hindsight.
    """
    file_path = arguments["file_path"]
    browser_type = arguments.get("browser_type", "Chrome")
    output_format = arguments.get("output_format", "jsonl")
    
    if not os.path.exists(file_path):
        return [types.TextContent(type="text", text=f"Error: File not found: {file_path}")]
    
    if not HINDSIGHT_PATH.exists():
        return [types.TextContent(type="text", text=f"Error: Hindsight tool not found at {HINDSIGHT_PATH}")]
    
    # Create temporary directory for processing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        output_dir = temp_path / "output"
        output_dir.mkdir(exist_ok=True)
        
        try:
            # Build Hindsight command
            input_for_hindsight = file_path
            # If a specific SQLite file like 'History' is provided, use its parent directory (profile dir)
            try:
                p = Path(file_path)
                if p.is_file() and p.name.lower() in {"history", "history.db", "places.sqlite"}:
                    input_for_hindsight = str(p.parent)
            except Exception:
                pass
            command = [
                sys.executable,
                str(HINDSIGHT_PATH),
                "-i", input_for_hindsight,
                "-o", str(output_dir / "analysis"),
                "-b", browser_type
            ]

            if output_format == "xlsx":
                command.extend(["-f", "XLSX"])
            elif output_format == "sqlite":
                command.extend(["-f", "SQLite"])
            else:
                # Default to JSONL, which is supported by Hindsight
                command.extend(["-f", "jsonl"])
            
            # Execute Hindsight
            logger.info(f"Running Hindsight command: {' '.join(command)}")
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=temp_path
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                err = (stderr.decode(errors='ignore') if stderr else '').strip()
                out = (stdout.decode(errors='ignore') if stdout else '').strip()
                error_msg = err or out or "Unknown error"
                return [types.TextContent(type="text", text=f"Hindsight analysis failed: {error_msg}")]
            
            # Read results
            if output_format == "jsonl":
                jsonl_file = output_dir / "analysis.jsonl"
                if not jsonl_file.exists():
                    # Fallback to output name used by Hindsight examples
                    jsonl_file = output_dir / "Hindsight.jsonl"

                if jsonl_file.exists():
                    items: List[Dict[str, Any]] = []
                    with open(jsonl_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                items.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue

                    # Store results for later access
                    analysis_id = f"history_{len(analysis_results) + 1}"
                    analysis_results[analysis_id] = {
                        "source_file": file_path,
                        "browser_type": browser_type,
                        "results": items,
                        "timestamp": asyncio.get_event_loop().time()
                    }

                    # Create summary
                    summary = create_analysis_summary(items)

                    return [types.TextContent(
                        type="text",
                        text=f"Analysis completed successfully!\n\n"
                             f"Analysis ID: {analysis_id}\n"
                             f"Source: {file_path}\n"
                             f"Browser: {browser_type}\n\n"
                             f"Summary:\n{summary}\n\n"
                             f"Use 'search_analysis_results' or 'get_analysis_summary' with ID '{analysis_id}' for detailed exploration."
                    )]
                else:
                    return [types.TextContent(type="text", text="Error: No JSONL output file found")]
            else:
                # For non-JSONL formats, still try to store results if a JSONL file exists
                jsonl_file = output_dir / "analysis.jsonl"
                if not jsonl_file.exists():
                    jsonl_file = output_dir / "Hindsight.jsonl"
                if jsonl_file.exists():
                    items: List[Dict[str, Any]] = []
                    with open(jsonl_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                items.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                    analysis_id = f"history_{len(analysis_results) + 1}"
                    analysis_results[analysis_id] = {
                        "source_file": file_path,
                        "browser_type": browser_type,
                        "results": items,
                        "timestamp": asyncio.get_event_loop().time()
                    }
                    summary = create_analysis_summary(items)
                    return [types.TextContent(
                        type="text",
                        text=f"Analysis completed successfully!\n\nAnalysis ID: {analysis_id}\nSource: {file_path}\nBrowser: {browser_type}\n\nSummary:\n{summary}"
                    )]
                # Otherwise, just confirm files created
                output_files = list(output_dir.glob("*"))
                return [types.TextContent(
                    type="text",
                    text=f"Analysis completed! Output files created: {[f.name for f in output_files]}"
                )]
                
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error during analysis: {str(e)}")]


async def analyze_chrome_profile(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """
    Analyze an entire Chrome profile directory.
    """
    profile_path = arguments["profile_path"]
    cache_path = arguments.get("cache_path")
    browser_type = arguments.get("browser_type", "Chrome")
    
    if not os.path.exists(profile_path):
        return [types.TextContent(type="text", text=f"Error: Profile path not found: {profile_path}")]
    
    if not HINDSIGHT_PATH.exists():
        return [types.TextContent(type="text", text=f"Error: Hindsight tool not found at {HINDSIGHT_PATH}")]
    
    # Create temporary directory for processing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        output_dir = temp_path / "output"
        output_dir.mkdir(exist_ok=True)
        
        try:
            # Build Hindsight command for profile analysis
            command = [
                sys.executable,
                str(HINDSIGHT_PATH),
                "-i", profile_path,
                "-o", str(output_dir / "profile_analysis"),
                "-b", browser_type,
                "-f", "jsonl"
            ]
            
            if cache_path:
                command.extend(["-c", cache_path])
            
            # Execute Hindsight
            logger.info(f"Running Hindsight profile analysis: {' '.join(command)}")
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=temp_path
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                return [types.TextContent(type="text", text=f"Profile analysis failed: {error_msg}")]
            
            # Read results
            jsonl_file = output_dir / "profile_analysis.jsonl"
            if not jsonl_file.exists():
                jsonl_file = output_dir / "Hindsight.jsonl"

            if jsonl_file.exists():
                items: List[Dict[str, Any]] = []
                with open(jsonl_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            items.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                
                # Store results
                analysis_id = f"profile_{len(analysis_results) + 1}"
                analysis_results[analysis_id] = {
                    "source_profile": profile_path,
                    "browser_type": browser_type,
                    "cache_path": cache_path,
                    "results": items,
                    "timestamp": asyncio.get_event_loop().time()
                }
                
                # Create comprehensive summary
                summary = create_analysis_summary(items)
                
                return [types.TextContent(
                    type="text",
                    text=f"Profile analysis completed successfully!\n\n"
                         f"Analysis ID: {analysis_id}\n"
                         f"Profile: {profile_path}\n"
                         f"Browser: {browser_type}\n"
                         f"Cache: {cache_path or 'Default location'}\n\n"
                         f"Summary:\n{summary}\n\n"
                         f"Use 'search_analysis_results' or 'get_analysis_summary' with ID '{analysis_id}' for detailed exploration."
                )]
            else:
                return [types.TextContent(type="text", text="Error: No JSON output file found")]
                
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error during profile analysis: {str(e)}")]


from datetime import datetime, time, timezone

def _parse_hindsight_timestamp(item: Dict[str, Any]) -> Optional[datetime]:
    """Helper to parse various timestamp formats from Hindsight artifacts."""
    from dateutil import parser
    for key in ['datetime', 'timestamp', 'visit_time', 'start_time', 'last_visit_time']:
        if key in item and item[key]:
            try:
                ts_val = item[key]
                if isinstance(ts_val, (int, float)):
                    if ts_val > 1e15: ts_val /= 1e9
                    elif ts_val > 1e12: ts_val /= 1e6
                    elif ts_val > 1e10: ts_val /= 1e3
                    if ts_val > 11644473600: ts_val -= 11644473600
                    return datetime.fromtimestamp(ts_val, tz=timezone.utc)
                elif isinstance(ts_val, str):
                    dt = parser.parse(ts_val)
                    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError, parser.ParserError):
                continue
    return None

async def search_analysis_results(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """
    Search through analysis results for specific patterns.
    """
    analysis_id = arguments["analysis_id"]
    search_term = arguments.get("search_term", "").lower()
    artifact_type = arguments.get("artifact_type")
    date_range = arguments.get("date_range")

    if analysis_id not in analysis_results:
        return [types.TextContent(type="text", text=f"Error: Analysis ID '{analysis_id}' not found")]

    start_date, end_date = None, None
    if date_range:
        try:
            if date_range.get("start_date"):
                start_date = datetime.fromisoformat(date_range["start_date"]).date()
            if date_range.get("end_date"):
                end_date = datetime.fromisoformat(date_range["end_date"]).date()
        except ValueError:
            return [types.TextContent(type="text", text="Error: Invalid date format. Please use YYYY-MM-DD.")]

    results = analysis_results[analysis_id]["results"]
    matches = []

    for item in results if isinstance(results, list) else []:
        if not isinstance(item, dict):
            continue

        # Filter by date range first
        if start_date or end_date:
            item_dt = _parse_hindsight_timestamp(item)
            if not item_dt:
                continue
            item_date = item_dt.date()
            if start_date and item_date < start_date:
                continue
            if end_date and item_date > end_date:
                continue

        # Filter by artifact type
        if artifact_type:
            category = (item.get('artifact') or item.get('type') or item.get('category') or '').lower()
            # Allow for partial matches, e.g., 'url' in 'chrome:history:url'
            if artifact_type.lower() not in category:
                continue

        # Filter by search term
        item_text = json.dumps(item).lower()
        if search_term and search_term not in item_text:
            continue
        
        matches.append({
            "category": item.get('artifact') or item.get('type') or item.get('category') or 'unknown',
            "item": item,
            "relevance": item_text.count(search_term) if search_term else 1
        })

    # Sort by relevance
    matches.sort(key=lambda x: x["relevance"], reverse=True)

    if not matches:
        return [types.TextContent(type="text", text=f"No matches found for the specified criteria in analysis '{analysis_id}'.")]

    # Format results
    result_text = f"Found {len(matches)} matches in analysis '{analysis_id}':\n\n"
    
    for i, match in enumerate(matches[:20]):  # Limit to top 20 results
        result_text += f"{i+1}. Category: {match['category']}\n"
        
        item = match['item']
        item_dt = _parse_hindsight_timestamp(item)
        if item_dt:
            result_text += f"   Timestamp: {item_dt.strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
        if 'url' in item:
            result_text += f"   URL: {item['url']}\n"
        if 'title' in item:
            result_text += f"   Title: {item['title']}\n"
        if 'visit_count' in item:
            result_text += f"   Visit Count: {item['visit_count']}\n"
        
        result_text += "\n"

    if len(matches) > 20:
        result_text += f"... and {len(matches) - 20} more matches\n"

    return [types.TextContent(type="text", text=result_text)]


async def get_analysis_summary(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """
    Get a detailed summary of analysis results.
    """
    analysis_id = arguments["analysis_id"]
    
    if analysis_id not in analysis_results:
        return [types.TextContent(type="text", text=f"Error: Analysis ID '{analysis_id}' not found")]
    
    analysis_data = analysis_results[analysis_id]
    results = analysis_data["results"]
    
    summary = f"Analysis Summary for ID: {analysis_id}\n"
    summary += "=" * 50 + "\n\n"
    
    summary += f"Source: {analysis_data.get('source_file', analysis_data.get('source_profile', 'Unknown'))}\n"
    summary += f"Browser: {analysis_data['browser_type']}\n"
    summary += f"Analysis Time: {analysis_data['timestamp']}\n\n"
    
    summary += create_analysis_summary(results)
    
    return [types.TextContent(type="text", text=summary)]


async def list_analyses(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """
    List stored analyses and metadata.
    """
    if not analysis_results:
        return [types.TextContent(type="text", text="No analyses stored yet.")]
    lines = ["Stored analyses:"]
    for analysis_id, data in analysis_results.items():
        source = data.get('source_file', data.get('source_profile', 'Unknown'))
        browser = data.get('browser_type', 'Unknown')
        lines.append(f"- {analysis_id}: {source} ({browser})")
    return [types.TextContent(type="text", text="\n".join(lines))]


def create_analysis_summary(results: Any) -> str:
    """
    Create a human-readable summary of analysis results.
    """
    summary = "Forensic Artifacts Found:\n"
    summary += "-" * 25 + "\n"
    
    # Results are a flat list of items (from JSONL)
    items_list: List[Dict[str, Any]] = results if isinstance(results, list) else []
    total_items = len(items_list)

    # Try to bucket by a common category field if present
    buckets: Dict[str, int] = {}
    for it in items_list:
        if not isinstance(it, dict):
            continue
        category = (it.get('artifact') or it.get('type') or it.get('category') or 'unknown')
        buckets[category] = buckets.get(category, 0) + 1

    for category, count in sorted(buckets.items(), key=lambda x: x[1], reverse=True)[:10]:
        summary += f"• {str(category).title()}: {count} items\n"

    # Heuristic highlights
    # Top visited URLs
    urls = [it for it in items_list if isinstance(it, dict) and 'url' in it]
    if urls:
        sorted_urls = sorted(urls, key=lambda x: x.get('visit_count', 0), reverse=True)
        top_urls = sorted_urls[:3]
        if top_urls:
            summary += "  Top visited: " + ", ".join([
                (u.get('url') or '')[:50] + ('...' if len(u.get('url') or '') > 50 else '') for u in top_urls
            ]) + "\n"

    # Recent downloads
    downloads = [it for it in items_list if isinstance(it, dict) and ('download' in str(it.get('artifact') or it.get('type') or '').lower() or 'target_path' in it)]
    if downloads:
        recent_downloads = sorted(downloads, key=lambda x: x.get('start_time', ''), reverse=True)[:3]
        if recent_downloads:
            summary += "  Recent downloads: " + ", ".join([
                (dl.get('target_path') or '').split('/')[-1] for dl in recent_downloads
            ]) + "\n"

    summary += f"\nTotal artifacts: {total_items}\n"
    
    return summary


@server.list_resources()
async def handle_list_resources() -> List[types.Resource]:
    """
    List available resources (analysis results).
    """
    resources = []
    
    for analysis_id, data in analysis_results.items():
        resources.append(
            types.Resource(
                uri=AnyUrl(f"hindsight://analysis/{analysis_id}"),
                name=f"Analysis {analysis_id}",
                description=f"Browser forensics analysis of {data.get('source_file', data.get('source_profile', 'Unknown'))}",
                mimeType="application/json"
            )
        )
    
    return resources


@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """
    Read a specific analysis resource.
    """
    uri_str = str(uri)
    
    if uri_str.startswith("hindsight://analysis/"):
        analysis_id = uri_str.split("/")[-1]
        
        if analysis_id in analysis_results:
            return json.dumps(analysis_results[analysis_id], indent=2)
        else:
            raise ValueError(f"Analysis {analysis_id} not found")
    
    raise ValueError(f"Unknown resource: {uri}")


class DuckOptions:
    def __init__(self):
        self.capabilities = {}
        self.server_name = "hindsight-mcp"
        self.server_version = "0.0.1"
        self.tools_changed = True
        self.resources_changed = True
        self.instructions = ""

async def main():
    """
    Main entry point for the MCP server.
    """
    # Run the server using stdin/stdout streams
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, DuckOptions())


if __name__ == "__main__":
    asyncio.run(main())
