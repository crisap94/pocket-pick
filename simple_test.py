#!/usr/bin/env python3
"""
Simple test of the Pocket Pick functionality without MCP protocol
"""
import tempfile
import os
from pathlib import Path
import sys

# Add the source directory to the path
sys.path.insert(0, 'src')

from mcp_server_pocket_pick.modules.functionality.add import add
from mcp_server_pocket_pick.modules.functionality.find import find
from mcp_server_pocket_pick.modules.functionality.list import list_items
from mcp_server_pocket_pick.modules.functionality.backup import backup
from mcp_server_pocket_pick.modules.data_types import AddCommand, FindCommand, ListCommand, BackupCommand
from mcp_server_pocket_pick.modules.security import SecurityError
from pydantic import ValidationError

def test_functionality():
    """Test basic functionality and security"""
    print("🚀 Testing Pocket Pick Functionality...")
    
    # Create temp database
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db_path = Path(db_path)
    
    try:
        # Test 1: Add item
        print("\n1️⃣ Testing add functionality...")
        result = add(AddCommand(
            id="test-123",
            text="This is a test item with some sample content",
            tags=["test", "demo", "functionality"],
            db_path=db_path
        ))
        print(f"✅ Added item: {result.id}")
        print(f"   Text: {result.text[:50]}...")
        print(f"   Tags: {result.tags}")
        
        # Test 2: Find items
        print("\n2️⃣ Testing find functionality...")
        results = find(FindCommand(
            text="test",
            limit=5,
            db_path=db_path
        ))
        print(f"✅ Found {len(results)} items")
        for item in results:
            print(f"   - {item.id}: {item.text[:30]}...")
        
        # Test 3: List items
        print("\n3️⃣ Testing list functionality...")
        all_items = list_items(ListCommand(
            limit=10,
            db_path=db_path
        ))
        print(f"✅ Listed {len(all_items)} items")
        
        # Test 4: Test security - dangerous database path
        print("\n4️⃣ Testing security (database path)...")
        try:
            dangerous_command = AddCommand(
                id="hack-attempt",
                text="malicious content",
                tags=["hack"],
                db_path=Path("/etc/malicious.db")
            )
            print("❌ Security failed - dangerous database path accepted!")
            return False
        except ValidationError as e:
            print("✅ Security working - dangerous database path blocked")
            print(f"   Error: {str(e)[:100]}...")
        
        # Test 5: Test backup functionality
        print("\n5️⃣ Testing backup functionality...")
        backup_fd, backup_path = tempfile.mkstemp(suffix='.db')
        os.close(backup_fd)
        backup_path = Path(backup_path)
        
        success = backup(BackupCommand(
            backup_path=backup_path,
            db_path=db_path
        ))
        
        if success and backup_path.exists():
            print("✅ Backup successful")
            print(f"   Backup size: {backup_path.stat().st_size} bytes")
            backup_path.unlink()  # Clean up
        else:
            print("❌ Backup failed")
            return False
        
        # Test 6: Test security - directory traversal in backup
        print("\n6️⃣ Testing security (directory traversal)...")
        try:
            dangerous_backup = BackupCommand(
                backup_path=Path("../../../tmp/stolen.db"),
                db_path=db_path
            )
            print("❌ Security failed - directory traversal accepted!")
            return False
        except ValidationError as e:
            print("✅ Security working - directory traversal blocked")
            print(f"   Error: {str(e)[:100]}...")
        
        print("\n🎉 All functionality tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
        
    finally:
        # Clean up
        if db_path.exists():
            db_path.unlink()

if __name__ == "__main__":
    success = test_functionality()
    if success:
        print("\n✅ Pocket Pick is working correctly with security protections!")
    else:
        print("\n❌ Tests failed!")
    sys.exit(0 if success else 1)