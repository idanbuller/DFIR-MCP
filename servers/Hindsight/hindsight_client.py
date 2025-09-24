import asyncio
import sys
import json
import os
from mcp import ClientSession, StdioServerParameters, stdio_client

async def main():
    """Client to call the Hindsight MCP server."""
    tool_name = "analyze_browser_history"
    tool_args = {
        "file_path": "/Users/ibuller/Desktop/Code/RTR/Windows/20250916_024807/History",
        "output_format": "jsonl"
    }

    # Make paths relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_path = os.path.join(script_dir, "hindsight_mcp_server.py")
    output_txt_path = os.path.join(script_dir, "hindsight_output.txt")

    server_params = StdioServerParameters(
        command=f"{sys.executable}",
        args=[server_path],
    )

    try:
        async with stdio_client(server_params, errlog=sys.stderr) as (read, write):
            async with ClientSession(read, write) as session:
                print("Calling Hindsight MCP server...")
                await session.initialize()
                result = await session.call_tool(tool_name, tool_args)
                if result.content:
                    print(f"--- Hindsight Analysis Complete ---")
                    # The full result is in the text, let's save it for the next step
                    with open(output_txt_path, "w") as f:
                        f.write(result.content[0].text)
                    print(result.content[0].text)
                    print(f"\n--- Output saved to {output_txt_path} ---")

    except Exception as e:
        print(f"An error occurred with Hindsight: {e}", file=sys.stderr)

if __name__ == "__main__":
    asyncio.run(main())
