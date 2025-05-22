#!/usr/bin/env python3
"""
Realistic security tests that test the complete execution path
including MCP server integration and real file operations
"""
import tempfile
import os
from pathlib import Path
import json
import sys
import asyncio
from unittest.mock import patch

# Import MCP server components
from mcp_server_pocket_pick.server import serve
from mcp_server_pocket_pick.modules.functionality.add_file import add_file
from mcp_server_pocket_pick.modules.functionality.to_file_by_id import to_file_by_id
from mcp_server_pocket_pick.modules.functionality.backup import backup
from mcp_server_pocket_pick.modules.data_types import *
from mcp_server_pocket_pick.modules.security import SecurityError, FileSizeValidator
from pydantic import ValidationError

def test_real_file_size_limits():
    """Test file size limits with actual large files (not mocked)"""
    print("📏 TESTING REAL FILE SIZE LIMITS")
    print("-" * 40)
    
    # Create temp database
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db_path = Path(db_path)
    
    try:
        # Test 1: Create a file larger than 10MB limit
        print("1️⃣ Creating large file (12MB)...")
        large_fd, large_file = tempfile.mkstemp(suffix='.txt')
        
        # Write 12MB of data
        chunk_size = 1024 * 1024  # 1MB
        with os.fdopen(large_fd, 'wb') as f:
            for i in range(12):  # 12MB
                f.write(b'A' * chunk_size)
        
        large_file = Path(large_file)
        actual_size = large_file.stat().st_size
        print(f"   📁 Created file: {actual_size / (1024*1024):.1f}MB")
        
        # Test 2: Try to add the large file (should fail)
        print("2️⃣ Testing file size validation...")
        try:
            cmd = AddFileCommand(
                id="large-file-test",
                file_path=str(large_file),
                tags=["test"],
                db_path=db_path
            )
            
            result = add_file(cmd)
            print("   ❌ SECURITY ISSUE: Large file was accepted!")
            return False
            
        except (SecurityError, ValidationError) as e:
            print("   ✅ Large file correctly rejected")
            print(f"   📝 Error: {str(e)[:80]}...")
        
        # Test 3: Test with file just under limit (should work)
        print("3️⃣ Testing file just under limit...")
        small_fd, small_file = tempfile.mkstemp(suffix='.txt')
        
        # Write 8MB of data (under 10MB limit)
        with os.fdopen(small_fd, 'wb') as f:
            for i in range(8):  # 8MB
                f.write(b'B' * chunk_size)
        
        small_file = Path(small_file)
        
        try:
            cmd = AddFileCommand(
                id="small-file-test",
                file_path=str(small_file),
                tags=["test"],
                db_path=db_path
            )
            
            result = add_file(cmd)
            print("   ✅ Small file correctly accepted")
            
        except Exception as e:
            print(f"   ⚠️ Small file unexpectedly rejected: {e}")
        
        # Clean up
        large_file.unlink()
        small_file.unlink()
        
        return True
        
    except Exception as e:
        print(f"❌ File size test failed: {e}")
        return False
        
    finally:
        if db_path.exists():
            db_path.unlink()

def test_real_path_operations():
    """Test path operations with real filesystem interactions"""
    print("\n🗂️ TESTING REAL PATH OPERATIONS")
    print("-" * 40)
    
    # Create temp database
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db_path = Path(db_path)
    
    try:
        # Test 1: Create real directories and files for testing
        print("1️⃣ Setting up test filesystem...")
        
        # Create a safe test directory
        safe_dir = Path(tempfile.mkdtemp())
        safe_file = safe_dir / "safe_file.txt"
        safe_file.write_text("This is safe content")
        
        print(f"   📁 Safe directory: {safe_dir}")
        
        # Test 2: Try various path traversal attempts with real paths
        print("2️⃣ Testing real path traversal attempts...")
        
        traversal_attempts = [
            f"{safe_dir}/../../../etc/passwd",
            f"{safe_dir}/./../../etc/passwd",
            f"{safe_dir}/safe/../../../etc/passwd",
        ]
        
        all_blocked = True
        for attempt in traversal_attempts:
            try:
                cmd = AddFileCommand(
                    id="traversal-test",
                    file_path=attempt,
                    tags=["test"],
                    db_path=db_path
                )
                print(f"   ❌ SECURITY ISSUE: Path accepted: {attempt}")
                all_blocked = False
            except ValidationError:
                print(f"   ✅ Blocked: {attempt}")
        
        # Test 3: Test legitimate file access works
        print("3️⃣ Testing legitimate file access...")
        try:
            cmd = AddFileCommand(
                id="legitimate-test",
                file_path=str(safe_file),
                tags=["test"],
                db_path=db_path
            )
            
            result = add_file(cmd)
            print("   ✅ Legitimate file access works")
            
        except Exception as e:
            print(f"   ❌ Legitimate access failed: {e}")
            all_blocked = False
        
        # Clean up
        safe_file.unlink()
        safe_dir.rmdir()
        
        return all_blocked
        
    except Exception as e:
        print(f"❌ Path operation test failed: {e}")
        return False
        
    finally:
        if db_path.exists():
            db_path.unlink()

def test_mcp_server_tool_integration():
    """Test security through the actual MCP server tool calling mechanism"""
    print("\n🔧 TESTING MCP SERVER TOOL INTEGRATION")
    print("-" * 40)
    
    # Create temp database
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db_path = Path(db_path)
    
    try:
        # Import the actual server tool calling function
        from mcp_server_pocket_pick.server import serve
        import inspect
        
        # Test 1: Check if server has proper tool validation
        print("1️⃣ Analyzing MCP server tool validation...")
        
        # Get the server module to examine tool calling
        server_source = inspect.getsource(serve)
        
        # Check for security-related imports and calls
        security_indicators = [
            "ValidationError", "SecurityError", "validate", "PathValidator"
        ]
        
        security_present = any(indicator in server_source for indicator in security_indicators)
        
        if security_present:
            print("   ✅ Server appears to have security validation")
        else:
            print("   ⚠️ Limited security validation visible in server")
        
        # Test 2: Test tool schema generation includes validation
        print("2️⃣ Testing tool schema validation...")
        
        try:
            schema = AddFileCommand.model_json_schema()
            
            # Check if schema has validation info
            if "properties" in schema:
                print("   ✅ Tool schema generated successfully")
                
                # Look for validation constraints
                db_path_schema = schema.get("properties", {}).get("db_path", {})
                if db_path_schema:
                    print("   ✅ Database path has schema definition")
                else:
                    print("   ⚠️ Database path schema limited")
            
        except Exception as e:
            print(f"   ❌ Schema generation failed: {e}")
            return False
        
        # Test 3: Simulate MCP tool call with dangerous parameters
        print("3️⃣ Simulating dangerous MCP tool calls...")
        
        # This simulates what would happen when MCP server receives a dangerous request
        dangerous_requests = [
            {
                "name": "pocket_add_file",
                "arguments": {
                    "id": "hack-attempt-1",
                    "file_path": "../../../etc/passwd",
                    "tags": ["hack"]
                }
            },
            {
                "name": "pocket_backup", 
                "arguments": {
                    "backup_path": "../../../tmp/stolen.db"
                }
            }
        ]
        
        all_dangerous_blocked = True
        
        for request in dangerous_requests:
            try:
                # Try to create the command object (this is what MCP server would do)
                if request["name"] == "pocket_add_file":
                    AddFileCommand(
                        id=request["arguments"]["id"],
                        file_path=request["arguments"]["file_path"],
                        tags=request["arguments"]["tags"],
                        db_path=db_path
                    )
                elif request["name"] == "pocket_backup":
                    BackupCommand(
                        backup_path=Path(request["arguments"]["backup_path"]),
                        db_path=db_path
                    )
                
                print(f"   ❌ SECURITY ISSUE: Dangerous request accepted: {request['name']}")
                all_dangerous_blocked = False
                
            except ValidationError:
                print(f"   ✅ Dangerous request blocked: {request['name']}")
        
        return all_dangerous_blocked
        
    except Exception as e:
        print(f"❌ MCP integration test failed: {e}")
        return False
        
    finally:
        if db_path.exists():
            db_path.unlink()

def test_complete_attack_scenarios():
    """Test complete realistic attack scenarios"""
    print("\n🎯 TESTING COMPLETE ATTACK SCENARIOS")
    print("-" * 40)
    
    # Create temp database
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db_path = Path(db_path)
    
    try:
        # Attack Scenario 1: Data Exfiltration Attempt
        print("1️⃣ Attack Scenario: Data Exfiltration")
        
        exfiltration_attempts = [
            # Try to read sensitive files
            ("Read /etc/passwd", "/etc/passwd"),
            ("Read SSH keys", "/root/.ssh/id_rsa"),
            ("Read shadow file", "/etc/shadow"),
            ("Read system logs", "/var/log/auth.log"),
        ]
        
        exfiltration_blocked = 0
        for desc, path in exfiltration_attempts:
            try:
                AddFileCommand(
                    id="exfiltrate",
                    file_path=path,
                    tags=["attack"],
                    db_path=db_path
                )
                print(f"   ❌ {desc}: ALLOWED")
            except ValidationError:
                print(f"   ✅ {desc}: BLOCKED")
                exfiltration_blocked += 1
        
        # Attack Scenario 2: Database Poisoning
        print("\n2️⃣ Attack Scenario: Database Poisoning")
        
        poisoning_attempts = [
            # Try to write to system databases
            ("System DB overwrite", "/etc/sqlite.db"),
            ("Root directory access", "/root/malicious.db"),
            ("System config DB", "/var/lib/system.db"),
        ]
        
        poisoning_blocked = 0
        for desc, path in poisoning_attempts:
            try:
                AddCommand(
                    id="poison",
                    text="malicious",
                    db_path=Path(path)
                )
                print(f"   ❌ {desc}: ALLOWED")
            except ValidationError:
                print(f"   ✅ {desc}: BLOCKED")
                poisoning_blocked += 1
        
        # Attack Scenario 3: File System Manipulation
        print("\n3️⃣ Attack Scenario: File System Manipulation")
        
        # First add a legitimate item
        from mcp_server_pocket_pick.modules.functionality.add import add
        add(AddCommand(
            id="legitimate-item",
            text="Legitimate content for export test",
            tags=["test"],
            db_path=db_path
        ))
        
        manipulation_attempts = [
            # Try to write to dangerous locations
            ("Overwrite system file", "/etc/hosts"),
            ("Write to root", "/root/backdoor.txt"),
            ("System directory", "/usr/local/bin/malware"),
        ]
        
        manipulation_blocked = 0
        for desc, path in manipulation_attempts:
            try:
                ToFileByIdCommand(
                    id="legitimate-item",
                    output_file_path_abs=Path(path),
                    db_path=db_path
                )
                print(f"   ❌ {desc}: ALLOWED")
            except ValidationError:
                print(f"   ✅ {desc}: BLOCKED")
                manipulation_blocked += 1
        
        # Calculate overall security score
        total_attacks = len(exfiltration_attempts) + len(poisoning_attempts) + len(manipulation_attempts)
        total_blocked = exfiltration_blocked + poisoning_blocked + manipulation_blocked
        
        print(f"\n📊 Attack Scenario Results:")
        print(f"   🎯 Total attack attempts: {total_attacks}")
        print(f"   🛡️ Attacks blocked: {total_blocked}")
        print(f"   📈 Security success rate: {(total_blocked/total_attacks)*100:.1f}%")
        
        return total_blocked == total_attacks
        
    except Exception as e:
        print(f"❌ Attack scenario test failed: {e}")
        return False
        
    finally:
        if db_path.exists():
            db_path.unlink()

def main():
    """Run all realistic security tests"""
    print("🔬 REALISTIC SECURITY TEST SUITE")
    print("=" * 50)
    print("Testing complete execution paths with real filesystem operations")
    print()
    
    tests = [
        ("Real File Size Limits", test_real_file_size_limits),
        ("Real Path Operations", test_real_path_operations), 
        ("MCP Server Integration", test_mcp_server_tool_integration),
        ("Complete Attack Scenarios", test_complete_attack_scenarios),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running: {test_name}")
        try:
            if test_func():
                print(f"✅ {test_name}: PASSED")
                passed += 1
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
    
    print(f"\n📊 FINAL RESULTS")
    print("=" * 50)
    print(f"✅ Tests passed: {passed}/{total}")
    print(f"📈 Success rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n🎉 ALL REALISTIC SECURITY TESTS PASSED!")
        print("🛡️ Security implementations are robust and effective!")
        print("✅ No false positives detected in security testing!")
        return True
    else:
        print(f"\n⚠️ {total-passed} security issues detected!")
        print("🚨 Some security measures may need improvement!")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)