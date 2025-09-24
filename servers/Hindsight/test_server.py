#!/usr/bin/env python3
"""
Test script for the Hindsight MCP Server

This script tests the basic functionality of the MCP server
without requiring a full MCP client setup.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path

# Import the server functions directly for testing
from hindsight_mcp_server import (
    analyze_browser_history,
    analyze_chrome_profile,
    search_analysis_results,
    get_analysis_summary,
    analysis_results,
    HINDSIGHT_PATH
)


async def test_server_functionality():
    """Test the core server functionality."""
    
    print("🧪 Testing Hindsight MCP Server")
    print("=" * 40)
    
    # Test 1: Check if Hindsight tool exists
    print("\n1. Checking Hindsight tool availability...")
    if HINDSIGHT_PATH.exists():
        print(f"✅ Hindsight tool found at: {HINDSIGHT_PATH}")
    else:
        print(f"❌ Hindsight tool not found at: {HINDSIGHT_PATH}")
        print("   Please ensure Hindsight is properly installed")
        return False
    
    # Test 2: Test with a sample browser history file (if available)
    print("\n2. Looking for sample browser history files...")
    
    # Common Chrome history locations
    chrome_paths = [
        Path.home() / "Library/Application Support/Google/Chrome/Default/History",  # macOS
        Path.home() / "AppData/Local/Google/Chrome/User Data/Default/History",      # Windows
        Path.home() / ".config/google-chrome/Default/History"                       # Linux
    ]
    
    sample_history = None
    for path in chrome_paths:
        if path.exists():
            sample_history = str(path)
            print(f"✅ Found Chrome history at: {sample_history}")
            break
    
    if not sample_history:
        print("⚠️  No Chrome history file found in default locations")
        print("   You can test manually by providing a history file path")
        
        # Create a dummy test to verify the function structure
        print("\n3. Testing function structure with invalid path...")
        try:
            result = await analyze_browser_history({
                "file_path": "/nonexistent/path",
                "browser_type": "Chrome",
                "output_format": "json"
            })
            
            if result and "Error: File not found" in result[0].text:
                print("✅ Error handling works correctly")
            else:
                print("❌ Unexpected result from invalid path test")
                
        except Exception as e:
            print(f"❌ Exception during invalid path test: {e}")
            return False
    else:
        # Test with full profile directory instead of copying single file
        history_path = Path(sample_history)
        profile_dir = str(history_path.parent)
        print(f"\n3. Testing analysis with full profile directory...\n   Profile: {profile_dir}")

        try:
            # Prefer profile analysis for completeness
            result = await analyze_chrome_profile({
                "profile_path": profile_dir,
                "browser_type": "Chrome"
            })

            if result and "completed successfully" in result[0].text:
                print("✅ Profile analysis completed successfully")

                # Extract analysis ID from result
                result_text = result[0].text
                if "Analysis ID:" in result_text:
                    analysis_id = result_text.split("Analysis ID: ")[1].split("\n")[0]
                    print(f"   Analysis ID: {analysis_id}")

                    # Test search functionality
                    print("\n4. Testing search functionality...")
                    search_result = await search_analysis_results({
                        "analysis_id": analysis_id,
                        "search_term": "google"
                    })

                    if search_result:
                        print("✅ Search functionality works")
                        if "Found" in search_result[0].text:
                            print(f"   {search_result[0].text.split('Found ')[1].split(' matches')[0]} matches found")

                    # Test summary functionality
                    print("\n5. Testing summary functionality...")
                    summary_result = await get_analysis_summary({
                        "analysis_id": analysis_id
                    })

                    if summary_result and "Analysis Summary" in summary_result[0].text:
                        print("✅ Summary functionality works")
                        # Show first few lines of summary
                        summary_lines = summary_result[0].text.split('\n')[:10]
                        for line in summary_lines:
                            if line.strip():
                                print(f"   {line}")
                        if len(summary_result[0].text.split('\n')) > 10:
                            print("   ...")

            else:
                print("❌ Profile analysis failed")
                if result:
                    print(f"   Result: {result[0].text}")
                return False

        except Exception as e:
            print(f"❌ Exception during profile analysis: {e}")
            return False
    
    print(f"\n📊 Analysis Results Storage: {len(analysis_results)} analyses stored")
    
    print("\n🎉 All tests completed successfully!")
    print("\nThe MCP server is ready to use. You can now:")
    print("1. Configure your AI assistant to use this MCP server")
    print("2. Use the server with the configuration in mcp_config.json")
    print("3. Run the server directly: python hindsight_mcp_server.py")
    
    return True


async def interactive_test():
    """Interactive test mode for manual testing."""
    
    print("\n🔧 Interactive Test Mode")
    print("=" * 30)
    
    while True:
        print("\nAvailable tests:")
        print("1. Test with custom history file")
        print("2. Test with custom profile directory")
        print("3. List stored analyses")
        print("4. Search in analysis")
        print("5. Get analysis summary")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == "1":
            file_path = input("Enter path to browser history file: ").strip()
            browser_type = input("Enter browser type (Chrome/Firefox/Brave) [Chrome]: ").strip() or "Chrome"
            
            try:
                result = await analyze_browser_history({
                    "file_path": file_path,
                    "browser_type": browser_type,
                    "output_format": "json"
                })
                print(f"\nResult: {result[0].text}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == "2":
            profile_path = input("Enter path to browser profile directory: ").strip()
            browser_type = input("Enter browser type (Chrome/Brave) [Chrome]: ").strip() or "Chrome"
            
            try:
                result = await analyze_chrome_profile({
                    "profile_path": profile_path,
                    "browser_type": browser_type
                })
                print(f"\nResult: {result[0].text}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == "3":
            if analysis_results:
                print(f"\nStored analyses ({len(analysis_results)}):")
                for analysis_id, data in analysis_results.items():
                    source = data.get('source_file', data.get('source_profile', 'Unknown'))
                    print(f"  {analysis_id}: {source}")
            else:
                print("\nNo analyses stored yet.")
                
        elif choice == "4":
            if not analysis_results:
                print("\nNo analyses available. Run an analysis first.")
                continue
                
            analysis_id = input("Enter analysis ID: ").strip()
            search_term = input("Enter search term: ").strip()
            
            try:
                result = await search_analysis_results({
                    "analysis_id": analysis_id,
                    "search_term": search_term
                })
                print(f"\nResult: {result[0].text}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == "5":
            if not analysis_results:
                print("\nNo analyses available. Run an analysis first.")
                continue
                
            analysis_id = input("Enter analysis ID: ").strip()
            
            try:
                result = await get_analysis_summary({
                    "analysis_id": analysis_id
                })
                print(f"\nResult: {result[0].text}")
            except Exception as e:
                print(f"Error: {e}")
                
        elif choice == "6":
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please try again.")


async def main():
    """Main test function."""
    
    print("Hindsight MCP Server Test Suite")
    print("=" * 40)
    
    # Run basic functionality tests
    success = await test_server_functionality()
    
    if success:
        # Ask if user wants interactive testing
        response = input("\nWould you like to run interactive tests? (y/n): ").strip().lower()
        if response in ['y', 'yes']:
            await interactive_test()
    else:
        print("\n❌ Basic tests failed. Please check the installation and try again.")


if __name__ == "__main__":
    asyncio.run(main())
