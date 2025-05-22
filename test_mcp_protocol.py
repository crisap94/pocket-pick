#!/usr/bin/env python3
"""
Test MCP server using actual JSON-RPC protocol
"""
import subprocess
import json
import sys
import time
import threading
import queue
from pathlib import Path

def read_lines(process, q):
    """Read lines from process stdout"""
    while True:
        line = process.stdout.readline()
        if not line:
            break
        q.put(line.strip())

def test_mcp_protocol():
    """Test MCP server using JSON-RPC protocol"""
    print("🚀 Testing MCP Server Protocol...")
    
    # Start MCP server
    cmd = ["uv", "run", "mcp-server-pocket-pick", "-d", "./test_protocol.db"]
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    
    # Queue for reading responses
    response_queue = queue.Queue()
    reader_thread = threading.Thread(target=read_lines, args=(process, response_queue))
    reader_thread.daemon = True
    reader_thread.start()
    
    try:
        time.sleep(0.5)  # Give server time to start
        
        # Test 1: Initialize
        print("\n1️⃣ Testing MCP initialization...")
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        }
        
        process.stdin.write(json.dumps(init_request) + "\n")
        process.stdin.flush()
        
        # Read response
        try:
            response = response_queue.get(timeout=2)
            init_response = json.loads(response)
            if "result" in init_response:
                print("✅ MCP initialization successful")
                print(f"   Protocol version: {init_response['result'].get('protocolVersion')}")
            else:
                print(f"❌ MCP initialization failed: {init_response}")
                return False
        except (queue.Empty, json.JSONDecodeError) as e:
            print(f"❌ Failed to get initialization response: {e}")
            return False
        
        # Test 2: List tools
        print("\n2️⃣ Testing tools/list...")
        tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        
        process.stdin.write(json.dumps(tools_request) + "\n")
        process.stdin.flush()
        
        try:
            response = response_queue.get(timeout=2)
            tools_response = json.loads(response)
            if "result" in tools_response and "tools" in tools_response["result"]:
                tools = tools_response["result"]["tools"]
                print(f"✅ Found {len(tools)} tools:")
                for tool in tools[:3]:  # Show first 3
                    print(f"   - {tool['name']}")
            else:
                print(f"❌ Tools list failed: {tools_response}")
                return False
        except (queue.Empty, json.JSONDecodeError) as e:
            print(f"❌ Failed to get tools response: {e}")
            return False
        
        # Test 3: Call pocket_add tool
        print("\n3️⃣ Testing pocket_add tool...")
        add_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "pocket_add",
                "arguments": {
                    "id": "protocol-test-123",
                    "text": "This is a test item via MCP protocol",
                    "tags": ["protocol", "test", "mcp"]
                }
            }
        }
        
        process.stdin.write(json.dumps(add_request) + "\n")
        process.stdin.flush()
        
        try:
            response = response_queue.get(timeout=2)
            add_response = json.loads(response)
            if "result" in add_response:
                print("✅ pocket_add successful")
                content = add_response["result"]["content"][0]["text"]
                print(f"   Response: {content[:80]}...")
            else:
                print(f"❌ pocket_add failed: {add_response}")
                return False
        except (queue.Empty, json.JSONDecodeError) as e:
            print(f"❌ Failed to get add response: {e}")
            return False
        
        # Test 4: Call pocket_find tool
        print("\n4️⃣ Testing pocket_find tool...")
        find_request = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "pocket_find",
                "arguments": {
                    "text": "protocol",
                    "limit": 5
                }
            }
        }
        
        process.stdin.write(json.dumps(find_request) + "\n")
        process.stdin.flush()
        
        try:
            response = response_queue.get(timeout=2)
            find_response = json.loads(response)
            if "result" in find_response:
                print("✅ pocket_find successful")
                content = find_response["result"]["content"][0]["text"]
                print(f"   Found: {content[:80]}...")
            else:
                print(f"❌ pocket_find failed: {find_response}")
                return False
        except (queue.Empty, json.JSONDecodeError) as e:
            print(f"❌ Failed to get find response: {e}")
            return False
        
        # Test 5: Test security - should fail
        print("\n5️⃣ Testing security (should fail)...")
        security_request = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "pocket_add_file",
                "arguments": {
                    "id": "security-test",
                    "file_path": "/etc/passwd",
                    "tags": ["security-test"]
                }
            }
        }
        
        process.stdin.write(json.dumps(security_request) + "\n")
        process.stdin.flush()
        
        try:
            response = response_queue.get(timeout=2)
            security_response = json.loads(response)
            if "error" in security_response:
                print("✅ Security working - dangerous operation blocked")
                print(f"   Error: {security_response['error']['message'][:80]}...")
            else:
                print("❌ Security failed - dangerous operation allowed!")
                return False
        except (queue.Empty, json.JSONDecodeError) as e:
            print(f"❌ Failed to get security response: {e}")
            return False
        
        print("\n🎉 All MCP protocol tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Protocol test failed: {e}")
        return False
        
    finally:
        # Clean up
        process.terminate()
        process.wait()
        
        # Remove test database
        test_db = Path("./test_protocol.db")
        if test_db.exists():
            test_db.unlink()
        
        print("🧹 Cleanup completed")

if __name__ == "__main__":
    success = test_mcp_protocol()
    if success:
        print("\n✅ MCP Server is working correctly!")
        print("🛡️ Security protections are active and effective!")
    else:
        print("\n❌ MCP Server tests failed!")
    sys.exit(0 if success else 1)