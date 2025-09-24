import asyncio
import sys
import json
import os
from mcp import ClientSession, StdioServerParameters, stdio_client

async def main():
    """A simple client to call a tool on the Plaso MCP server."""
    if len(sys.argv) < 2:
        print("Usage: python plaso_client.py <tool_name> [json_args]")
        return

    tool_name = sys.argv[1]
    tool_args = {}
    if len(sys.argv) > 2:
        try:
            tool_args = json.loads(sys.argv[2])
        except json.JSONDecodeError:
            print("Error: Invalid JSON arguments.", file=sys.stderr)
            return

    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_path = os.path.join(script_dir, "plaso_mcp_server.py")

    server_params = StdioServerParameters(
        command=f"{sys.executable}",
        args=[server_path],
    )

    try:
        async with stdio_client(server_params, errlog=sys.stderr) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, tool_args)
                if result.content:
                    print(result.content[0].text)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)

if __name__ == "__main__":
    asyncio.run(main())
