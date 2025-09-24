import asyncio
import sys
import os
from mcp import ClientSession, StdioServerParameters, stdio_client

async def main():
    """Client to call the Hayabusa MCP server's csv_timeline tool."""
    tool_name = "csv_timeline"
    tool_args = {
        "evtx_dir": "/Users/ibuller/Desktop/Code/RTR/Windows/20250916_024807/Triage/c/Windows/System32/winevt/logs",
        "output": "/Users/ibuller/Desktop/Code/RTR/Windows/20250916_024807/Triage/c/timeline.csv",
        "overwrite": True
    }

    # Make server path relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_path = os.path.join(script_dir, "hayabusa_mcp_server.py")

    server_params = StdioServerParameters(
        command=f"{sys.executable}",
        args=[server_path],
    )

    try:
        async with stdio_client(server_params, errlog=sys.stderr) as (read, write):
            async with ClientSession(read, write) as session:
                print("Calling Hayabusa MCP server...")
                await session.initialize()
                result = await session.call_tool(tool_name, tool_args)
                if result.content:
                    print(f"--- Hayabusa Analysis Complete ---")
                    print(result.content[0].text)

    except Exception as e:
        print(f"An error occurred with Hayabusa: {e}", file=sys.stderr)

if __name__ == "__main__":
    asyncio.run(main())
