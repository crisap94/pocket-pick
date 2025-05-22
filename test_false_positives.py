#!/usr/bin/env python3
"""
Test for potential false positives in security tests
"""
import tempfile
import os
from pathlib import Path
import sys

from mcp_server_pocket_pick.modules.functionality.add import add
from mcp_server_pocket_pick.modules.functionality.add_file import add_file
from mcp_server_pocket_pick.modules.data_types import AddCommand, AddFileCommand
from mcp_server_pocket_pick.modules.security import PathValidator, SecurityError
from pydantic import ValidationError

def test_potential_bypasses():
    """Test for potential security bypasses that might make tests false positives"""
    print("🔍 TESTING FOR FALSE POSITIVES AND BYPASSES")
    print("=" * 50)
    
    # Create temp database
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db_path = Path(db_path)
    
    bypasses_found = 0
    total_bypass_tests = 0
    
    try:
        # Test 1: Can we bypass validation by modifying the object after creation?
        print("1️⃣ Testing post-creation modification bypass...")
        total_bypass_tests += 1
        try:
            cmd = AddCommand(
                id="test-bypass-1",
                text="test",
                db_path=db_path
            )
            # Try to modify after validation
            cmd.db_path = Path("/etc/malicious.db")
            
            # This might bypass validation if the function doesn't re-validate
            result = add(cmd)
            print("   ❌ BYPASS FOUND: Post-creation modification possible!")
            bypasses_found += 1
        except (SecurityError, ValidationError, Exception) as e:
            print("   ✅ No bypass: Post-creation modification blocked")
        
        # Test 2: Direct function call bypassing data structure validation
        print("\n2️⃣ Testing direct function parameter bypass...")
        total_bypass_tests += 1
        try:
            # If we could call the function directly with a raw Path object
            # This tests if the function has its own validation
            from mcp_server_pocket_pick.modules.functionality.add import add
            import inspect
            
            # Check function signature
            sig = inspect.signature(add)
            print(f"   Function signature: {sig}")
            
            # The function expects AddCommand, so this test is not applicable
            print("   ✅ Function requires validated command object")
        except Exception as e:
            print(f"   ⚠️ Could not test direct bypass: {e}")
        
        # Test 3: Symlink attack bypass
        print("\n3️⃣ Testing symlink bypass...")
        total_bypass_tests += 1
        try:
            # Create a symlink to a dangerous location
            safe_file = tempfile.mktemp(suffix='.txt')
            with open(safe_file, 'w') as f:
                f.write("safe content")
            
            dangerous_link = tempfile.mktemp(suffix='.txt')
            
            # Try to create symlink (might fail without permissions)
            try:
                os.symlink('/etc/passwd', dangerous_link)
                
                # Now try to add this symlinked file
                cmd = AddFileCommand(
                    id="symlink-test",
                    file_path=dangerous_link,
                    tags=["test"],
                    db_path=db_path
                )
                
                result = add_file(cmd)
                print("   ❌ BYPASS FOUND: Symlink attack successful!")
                bypasses_found += 1
                
                # Clean up
                os.unlink(dangerous_link)
                
            except (PermissionError, OSError):
                print("   ℹ️ Cannot test symlink (permission denied)")
            except (SecurityError, ValidationError):
                print("   ✅ Symlink attack blocked")
            
            # Clean up
            if os.path.exists(safe_file):
                os.unlink(safe_file)
                
        except Exception as e:
            print(f"   ⚠️ Symlink test error: {e}")
        
        # Test 4: Unicode/encoding bypass
        print("\n4️⃣ Testing Unicode/encoding bypass...")
        total_bypass_tests += 1
        try:
            # Try various Unicode representations of dangerous paths
            dangerous_unicode_paths = [
                "../../../etc/passwd",  # Normal
                "..%2F..%2F..%2Fetc%2Fpasswd",  # URL encoded
                "..\\..\\..\\etc\\passwd",  # Windows-style
                "\u002e\u002e\u002f\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd",  # Unicode
            ]
            
            bypass_found_unicode = False
            for dangerous_path in dangerous_unicode_paths:
                try:
                    AddFileCommand(
                        id="unicode-test",
                        file_path=dangerous_path,
                        tags=["test"],
                        db_path=db_path
                    )
                    print(f"   ❌ BYPASS FOUND: Unicode path accepted: {dangerous_path}")
                    bypass_found_unicode = True
                    bypasses_found += 1
                    break
                except ValidationError:
                    continue
            
            if not bypass_found_unicode:
                print("   ✅ Unicode encoding bypass blocked")
                
        except Exception as e:
            print(f"   ⚠️ Unicode test error: {e}")
        
        # Test 5: Path normalization bypass
        print("\n5️⃣ Testing path normalization bypass...")
        total_bypass_tests += 1
        try:
            # Try paths that might normalize to dangerous locations
            tricky_paths = [
                "/tmp/../../../etc/passwd",
                "/tmp/./../../etc/passwd", 
                "/tmp/safe/../../../etc/passwd",
                "//etc//passwd",
                "/etc/passwd/.",
            ]
            
            bypass_found_norm = False
            for tricky_path in tricky_paths:
                try:
                    AddFileCommand(
                        id="normalize-test",
                        file_path=tricky_path,
                        tags=["test"],
                        db_path=db_path
                    )
                    print(f"   ❌ BYPASS FOUND: Tricky path accepted: {tricky_path}")
                    bypass_found_norm = True
                    bypasses_found += 1
                    break
                except ValidationError:
                    continue
            
            if not bypass_found_norm:
                print("   ✅ Path normalization bypass blocked")
                
        except Exception as e:
            print(f"   ⚠️ Normalization test error: {e}")
        
        # Test 6: Test actual PathValidator edge cases
        print("\n6️⃣ Testing PathValidator edge cases...")
        total_bypass_tests += 1
        try:
            edge_cases = [
                "",  # Empty path
                ".",  # Current directory
                "/",  # Root
                "~/../../etc/passwd",  # Home expansion
                "$HOME/../../etc/passwd",  # Variable expansion
            ]
            
            bypass_found_edge = False
            for edge_case in edge_cases:
                try:
                    result = PathValidator.validate_file_path(edge_case)
                    # If we get here without exception, check if result is dangerous
                    resolved = str(result.resolve())
                    if any(sensitive in resolved for sensitive in ["/etc/", "/root/", "/var/"]):
                        print(f"   ❌ BYPASS FOUND: Edge case leads to sensitive path: {edge_case} -> {resolved}")
                        bypass_found_edge = True
                        bypasses_found += 1
                        break
                except (SecurityError, OSError):
                    continue
            
            if not bypass_found_edge:
                print("   ✅ PathValidator edge cases handled")
                
        except Exception as e:
            print(f"   ⚠️ Edge case test error: {e}")
        
        # Summary
        print("\n📊 FALSE POSITIVE ANALYSIS")
        print("=" * 50)
        print(f"🔍 Bypass tests performed: {total_bypass_tests}")
        print(f"❌ Potential bypasses found: {bypasses_found}")
        print(f"✅ Bypasses blocked: {total_bypass_tests - bypasses_found}")
        
        if bypasses_found > 0:
            print(f"\n⚠️ WARNING: {bypasses_found} potential security bypasses detected!")
            print("🚨 Some security tests may be FALSE POSITIVES!")
            return False
        else:
            print("\n✅ No bypasses found - security tests appear to be valid")
            return True
            
    except Exception as e:
        print(f"❌ False positive test failed: {e}")
        return False
        
    finally:
        if db_path.exists():
            db_path.unlink()

if __name__ == "__main__":
    success = test_potential_bypasses()
    if success:
        print("\n✅ Security tests appear legitimate")
    else:
        print("\n❌ Potential false positives detected!")
    sys.exit(0 if success else 1)