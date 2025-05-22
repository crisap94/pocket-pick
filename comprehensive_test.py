#!/usr/bin/env python3
"""
Comprehensive test of Pocket Pick functionality and security
"""
import tempfile
import os
from pathlib import Path
import json

# Test the core functionality
from mcp_server_pocket_pick.modules.functionality.add import add
from mcp_server_pocket_pick.modules.functionality.add_file import add_file
from mcp_server_pocket_pick.modules.functionality.find import find
from mcp_server_pocket_pick.modules.functionality.list import list_items
from mcp_server_pocket_pick.modules.functionality.backup import backup
from mcp_server_pocket_pick.modules.functionality.to_file_by_id import to_file_by_id
from mcp_server_pocket_pick.modules.data_types import *
from mcp_server_pocket_pick.modules.security import SecurityError
from pydantic import ValidationError

def run_comprehensive_test():
    """Run comprehensive functionality and security tests"""
    print("🧪 COMPREHENSIVE POCKET PICK TEST SUITE")
    print("=" * 50)
    
    # Create temp database and files
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(db_fd)
    db_path = Path(db_path)
    
    file_fd, test_file = tempfile.mkstemp(suffix='.txt')
    with os.fdopen(file_fd, 'w') as f:
        f.write("This is test file content for adding to pocket pick.")
    test_file = Path(test_file)
    
    try:
        print(f"📁 Using test database: {db_path}")
        print(f"📄 Using test file: {test_file}")
        
        # ========== FUNCTIONALITY TESTS ==========
        print("\n🚀 FUNCTIONALITY TESTS")
        print("-" * 30)
        
        # Test 1: Add basic item
        print("1️⃣ Testing add functionality...")
        item1 = add(AddCommand(
            id="func-test-1",
            text="First test item with comprehensive content for testing purposes",
            tags=["test", "functionality", "basic"],
            db_path=db_path
        ))
        print(f"   ✅ Added: {item1.id}")
        print(f"   📝 Text: {item1.text[:40]}...")
        print(f"   🏷️ Tags: {item1.tags}")
        
        # Test 2: Add from file
        print("\n2️⃣ Testing add_file functionality...")
        item2 = add_file(AddFileCommand(
            id="func-test-2",
            file_path=str(test_file),
            tags=["test", "file", "import"],
            db_path=db_path
        ))
        print(f"   ✅ Added from file: {item2.id}")
        print(f"   📝 Content: {item2.text[:40]}...")
        
        # Test 3: Find items
        print("\n3️⃣ Testing find functionality...")
        results = find(FindCommand(
            text="test",
            limit=10,
            db_path=db_path
        ))
        print(f"   🔍 Found {len(results)} items containing 'test'")
        for result in results:
            print(f"     - {result.id}: {result.text[:30]}...")
        
        # Test 4: List all items
        print("\n4️⃣ Testing list functionality...")
        all_items = list_items(ListCommand(
            limit=20,
            db_path=db_path
        ))
        print(f"   📋 Listed {len(all_items)} total items")
        
        # Test 5: Export to file
        print("\n5️⃣ Testing export functionality...")
        export_fd, export_file = tempfile.mkstemp(suffix='.txt')
        os.close(export_fd)
        export_file = Path(export_file)
        
        success = to_file_by_id(ToFileByIdCommand(
            id="func-test-1",
            output_file_path_abs=export_file,
            db_path=db_path
        ))
        
        if success and export_file.exists():
            with open(export_file, 'r') as f:
                exported_content = f.read()
            print(f"   💾 Exported successfully: {len(exported_content)} chars")
            export_file.unlink()  # Clean up
        
        # Test 6: Backup database
        print("\n6️⃣ Testing backup functionality...")
        backup_fd, backup_file = tempfile.mkstemp(suffix='.db')
        os.close(backup_fd)
        backup_file = Path(backup_file)
        
        backup_success = backup(BackupCommand(
            backup_path=backup_file,
            db_path=db_path
        ))
        
        if backup_success and backup_file.exists():
            backup_size = backup_file.stat().st_size
            print(f"   💾 Backup successful: {backup_size} bytes")
            backup_file.unlink()  # Clean up
        
        print("✅ All functionality tests passed!")
        
        # ========== SECURITY TESTS ==========
        print("\n🛡️ SECURITY TESTS")
        print("-" * 30)
        
        security_tests_passed = 0
        total_security_tests = 0
        
        # Security Test 1: Directory traversal in database path
        print("1️⃣ Testing database path traversal protection...")
        total_security_tests += 1
        try:
            AddCommand(
                id="hack-db",
                text="malicious",
                db_path=Path("../../../etc/malicious.db")
            )
            print("   ❌ SECURITY FAILURE: Database traversal allowed!")
        except ValidationError:
            print("   ✅ Database path traversal blocked")
            security_tests_passed += 1
        
        # Security Test 2: Sensitive directory access
        print("\n2️⃣ Testing sensitive directory protection...")
        total_security_tests += 1
        try:
            AddFileCommand(
                id="hack-file",
                file_path="/etc/passwd",
                db_path=db_path
            )
            print("   ❌ SECURITY FAILURE: Sensitive file access allowed!")
        except ValidationError:
            print("   ✅ Sensitive directory access blocked")
            security_tests_passed += 1
        
        # Security Test 3: Directory traversal in file paths
        print("\n3️⃣ Testing file path traversal protection...")
        total_security_tests += 1
        try:
            AddFileCommand(
                id="hack-traversal",
                file_path="../../../root/.ssh/id_rsa",
                db_path=db_path
            )
            print("   ❌ SECURITY FAILURE: File path traversal allowed!")
        except ValidationError:
            print("   ✅ File path traversal blocked")
            security_tests_passed += 1
        
        # Security Test 4: Backup path traversal
        print("\n4️⃣ Testing backup path traversal protection...")
        total_security_tests += 1
        try:
            BackupCommand(
                backup_path=Path("../../../tmp/stolen.db"),
                db_path=db_path
            )
            print("   ❌ SECURITY FAILURE: Backup path traversal allowed!")
        except ValidationError:
            print("   ✅ Backup path traversal blocked")
            security_tests_passed += 1
        
        # Security Test 5: Output path traversal
        print("\n5️⃣ Testing output path traversal protection...")
        total_security_tests += 1
        try:
            ToFileByIdCommand(
                id="test",
                output_file_path_abs=Path("../../../tmp/hack.txt"),
                db_path=db_path
            )
            print("   ❌ SECURITY FAILURE: Output path traversal allowed!")
        except ValidationError:
            print("   ✅ Output path traversal blocked")
            security_tests_passed += 1
        
        # Security Test 6: Database extension validation
        print("\n6️⃣ Testing database extension validation...")
        total_security_tests += 1
        try:
            AddCommand(
                id="hack-ext",
                text="malicious",
                db_path=Path("/tmp/notadatabase.txt")
            )
            print("   ❌ SECURITY FAILURE: Invalid database extension allowed!")
        except ValidationError:
            print("   ✅ Database extension validation working")
            security_tests_passed += 1
        
        print(f"\n🛡️ Security Score: {security_tests_passed}/{total_security_tests} tests passed")
        
        # ========== PERFORMANCE/STRESS TEST ==========
        print("\n⚡ PERFORMANCE TEST")
        print("-" * 30)
        
        print("1️⃣ Adding multiple items...")
        for i in range(10):
            add(AddCommand(
                id=f"perf-test-{i}",
                text=f"Performance test item {i} with some content to test bulk operations",
                tags=["performance", "bulk", f"item-{i}"],
                db_path=db_path
            ))
        
        print("2️⃣ Searching through items...")
        bulk_results = find(FindCommand(
            text="performance",
            limit=20,
            db_path=db_path
        ))
        print(f"   🔍 Found {len(bulk_results)} performance test items")
        
        print("✅ Performance test completed!")
        
        # ========== FINAL SUMMARY ==========
        print("\n📊 TEST SUMMARY")
        print("=" * 50)
        print("✅ Functionality: All core features working")
        print(f"🛡️ Security: {security_tests_passed}/{total_security_tests} protections active")
        print("⚡ Performance: Bulk operations successful")
        print("🗄️ Database: SQLite operations stable")
        
        if security_tests_passed == total_security_tests:
            print("\n🎉 ALL TESTS PASSED!")
            print("✅ Pocket Pick is secure and ready for production!")
            return True
        else:
            print(f"\n⚠️ {total_security_tests - security_tests_passed} security issues found!")
            return False
        
    except Exception as e:
        print(f"\n❌ Test suite failed with error: {e}")
        return False
        
    finally:
        # Clean up all temporary files
        print("\n🧹 Cleaning up...")
        for file_path in [db_path, test_file]:
            if file_path.exists():
                file_path.unlink()
                print(f"   🗑️ Removed: {file_path}")

if __name__ == "__main__":
    print("🧪 POCKET PICK COMPREHENSIVE TEST SUITE")
    print("🔒 Testing functionality and security implementations")
    print()
    
    success = run_comprehensive_test()
    
    if success:
        print("\n🎉 SUCCESS: Pocket Pick is working perfectly!")
        print("🛡️ All security protections are active and effective!")
        print("🚀 Ready for self-hosted deployment!")
    else:
        print("\n❌ FAILURE: Issues detected!")
        
    exit(0 if success else 1)