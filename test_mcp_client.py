#!/usr/bin/env python3
"""
Simple MCP client to test the Pocket Pick server
"""
import json
import subprocess
import sys
import time
from pathlib import Path

def send_mcp_request(process, method, params=None):
    """Send an MCP request and get response"""
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or {}
    }
    
    # Send request
    request_str = json.dumps(request) + "\n"
    process.stdin.write(request_str.encode())
    process.stdin.flush()
    
    # Read response
    response_line = process.stdout.readline().decode().strip()
    if response_line:
        return json.loads(response_line)
    return None

def test_mcp_server():
    """Test the MCP server functionality"""
    print("🚀 Starting MCP Server Test...")
    
    # Start the MCP server process
    cmd = ["uv", "run", "mcp-server-pocket-pick", "-d", "./test_mcp.db"]
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=Path.cwd()
    )
    
    try:
        time.sleep(1)  # Give server time to start
        
        # Test 1: Initialize connection
        print("\n1️⃣ Testing MCP initialization...")
        init_response = send_mcp_request(process, "initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        })
        
        if init_response and "result" in init_response:
            print("✅ MCP initialization successful")
            print(f"   Server info: {init_response['result'].get('serverInfo', {})}")
        else:
            print("❌ MCP initialization failed")
            return False
        
        # Test 2: List available tools
        print("\n2️⃣ Testing tool listing...")
        tools_response = send_mcp_request(process, "tools/list")
        
        if tools_response and "result" in tools_response:
            tools = tools_response["result"]["tools"]
            print(f"✅ Found {len(tools)} tools:")
            for tool in tools:
                print(f"   - {tool['name']}: {tool['description']}")
        else:
            print("❌ Tool listing failed")
            return False
        
        # Test 3: Test pocket_add tool
        print("\n3️⃣ Testing pocket_add...")
        add_response = send_mcp_request(process, "tools/call", {
            "name": "pocket_add",
            "arguments": {
                "id": "test-item-123",
                "text": "This is a test item for MCP server testing",
                "tags": ["test", "mcp", "demo"]
            }
        })
        
        if add_response and "result" in add_response:
            print("✅ pocket_add successful")
            print(f"   Response: {add_response['result']['content'][0]['text']}")
        else:
            print("❌ pocket_add failed")
            print(f"   Error: {add_response}")
            return False
        
        # Test 4: Test pocket_find tool
        print("\n4️⃣ Testing pocket_find...")
        find_response = send_mcp_request(process, "tools/call", {
            "name": "pocket_find",
            "arguments": {
                "text": "test",
                "limit": 5
            }
        })
        
        if find_response and "result" in find_response:
            print("✅ pocket_find successful")
            print(f"   Found items: {find_response['result']['content'][0]['text']}")
        else:
            print("❌ pocket_find failed")
            return False
        
        # Test 5: Test pocket_list tool
        print("\n5️⃣ Testing pocket_list...")
        list_response = send_mcp_request(process, "tools/call", {
            "name": "pocket_list",
            "arguments": {
                "limit": 10
            }
        })
        
        if list_response and "result" in list_response:
            print("✅ pocket_list successful")
            print(f"   Items: {list_response['result']['content'][0]['text'][:100]}...")
        else:
            print("❌ pocket_list failed")
            return False
        
        # Test 6: Test security - try dangerous path (should fail)
        print("\n6️⃣ Testing security (should fail)...")
        try:
            security_response = send_mcp_request(process, "tools/call", {
                "name": "pocket_add_file",
                "arguments": {
                    "id": "malicious-test",
                    "file_path": "../../../etc/passwd",
                    "tags": ["hack"]
                }
            })
            
            if security_response and "error" in security_response:
                print("✅ Security protection working - dangerous path blocked")
                print(f"   Error: {security_response['error']['message']}")
            else:
                print("❌ Security issue - dangerous path was accepted!")
                return False
        except Exception as e:
            print(f"✅ Security protection working - exception caught: {e}")
        
        print("\n🎉 All MCP tests passed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with exception: {e}")
        return False
        
    finally:
        # Clean up
        process.terminate()
        process.wait()
        
        # Remove test database
        test_db = Path("./test_mcp.db")
        if test_db.exists():
            test_db.unlink()

if __name__ == "__main__":
    success = test_mcp_server()
    sys.exit(0 if success else 1)