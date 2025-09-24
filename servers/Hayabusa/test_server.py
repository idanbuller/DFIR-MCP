#!/usr/bin/env python3
"""
Test script for the Hayabusa MCP Server

Quickly exercises core functionality without a full MCP client.
"""

import asyncio
import os
from pathlib import Path

# Ensure the server module can be found by adding the project root to the path
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from servers.Hayabusa.hayabusa_mcp_server import (
    _tool_hayabusa_version,
    _find_hayabusa_binary
)


async def main():
    print("Hayabusa MCP Server Test")
    print("=" * 30)

    # 1) Check if Hayabusa binary can be found
    print("\n1) Checking for Hayabusa binary...")
    binary_path = _find_hayabusa_binary()
    if not binary_path:
        print("❌ ERROR: Hayabusa binary not found.")
        print("Please ensure the binary is at 'servers/Hayabusa/bin/hayabusa' or HAYABUSA_PATH is set.")
        return
    print(f"✅ Found Hayabusa binary at: {binary_path}")


    # 2) Show Hayabusa version
    print("\n2) Getting Hayabusa version via the server's tool function...")
    try:
        version_result = await _tool_hayabusa_version()
        print("--- Server Response ---")
        print(version_result[0].text)
        print("-----------------------")
    except Exception as e:
        print(f"❌ ERROR calling version tool: {e}")
        return

    print("\n✅ Test completed successfully.")


if __name__ == "__main__":
    asyncio.run(main())
