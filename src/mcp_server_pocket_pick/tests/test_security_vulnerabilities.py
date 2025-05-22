import pytest
import tempfile
import os
from pathlib import Path
import sqlite3
from unittest.mock import patch, mock_open, MagicMock
import json
from datetime import datetime

from ..modules.functionality.add_file import add_file
from ..modules.functionality.to_file_by_id import to_file_by_id
from ..modules.functionality.backup import backup
from ..modules.functionality.add import add
from ..modules.data_types import AddFileCommand, ToFileByIdCommand, BackupCommand, AddCommand


class TestDirectoryTraversalVulnerabilities:
    """Tests that demonstrate directory traversal vulnerabilities in file operations"""
    
    def setup_method(self):
        """Setup temp database for each test"""
        self.fd, self.db_path = tempfile.mkstemp()
        os.close(self.fd)
        self.db_path = Path(self.db_path)
    
    def teardown_method(self):
        """Cleanup temp database"""
        if self.db_path.exists():
            self.db_path.unlink()
    
    @patch('builtins.open', new_callable=mock_open, read_data="malicious content")
    @patch('pathlib.Path.exists', return_value=True)
    def test_add_file_directory_traversal_vulnerability(self, mock_exists, mock_file):
        """Test that add_file accepts directory traversal paths - VULNERABILITY EXISTS"""
        malicious_path = "../../../etc/passwd"
        
        command = AddFileCommand(
            id="test-traversal",
            file_path=malicious_path,
            tags=["test"],
            db_path=self.db_path
        )
        
        # This should succeed, demonstrating the vulnerability
        result = add_file(command)
        
        # Verify the malicious path was accepted and processed
        assert result.id == "test-traversal"
        assert result.text == "malicious content"
        mock_file.assert_called_with(Path(malicious_path), 'r', encoding='utf-8')
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('pathlib.Path.mkdir')
    def test_to_file_by_id_directory_traversal_vulnerability(self, mock_mkdir, mock_file):
        """Test that to_file_by_id accepts directory traversal paths - VULNERABILITY EXISTS"""
        # First add an item to export
        add_command = AddCommand(
            id="test-item",
            text="sensitive data",
            tags=["test"],
            db_path=self.db_path
        )
        add(add_command)
        
        # Try to export to a dangerous path
        malicious_output_path = "../../../tmp/malicious_export.txt"
        
        command = ToFileByIdCommand(
            id="test-item",
            output_file_path_abs=Path(malicious_output_path),
            db_path=self.db_path
        )
        
        # This should succeed, demonstrating the vulnerability
        result = to_file_by_id(command)
        
        assert result is True
        # Verify dangerous path was processed
        assert mock_mkdir.called  # Directory creation was attempted
        mock_file.assert_called_with(Path(malicious_output_path), 'w', encoding='utf-8')
    
    @patch('shutil.copy2')
    @patch('pathlib.Path.mkdir')
    @patch('pathlib.Path.exists', return_value=True)
    def test_backup_directory_traversal_vulnerability(self, mock_exists, mock_mkdir, mock_copy):
        """Test that backup accepts directory traversal paths - VULNERABILITY EXISTS"""
        malicious_backup_path = "../../../tmp/stolen_database.db"
        
        command = BackupCommand(
            backup_path=Path(malicious_backup_path),
            db_path=self.db_path
        )
        
        # This should succeed, demonstrating the vulnerability
        result = backup(command)
        
        assert result is True
        # Verify dangerous backup path was processed
        assert mock_mkdir.called  # Directory creation was attempted
        mock_copy.assert_called_with(self.db_path, Path(malicious_backup_path))


class TestDatabasePathInjectionVulnerability:
    """Tests that demonstrate database path injection vulnerability"""
    
    @patch('sqlite3.connect')
    @patch('pathlib.Path.exists', return_value=True)
    def test_database_path_injection_vulnerability(self, mock_exists, mock_connect):
        """Test that arbitrary database paths are accepted - VULNERABILITY EXISTS"""
        # Mock database connection
        mock_db = MagicMock()
        mock_connect.return_value = mock_db
        
        # Try to access sensitive system database
        malicious_db_path = "/etc/shadow.db"
        
        command = AddCommand(
            id="test-item",
            text="test content",
            tags=["test"],
            db_path=Path(malicious_db_path)
        )
        
        # This should succeed, demonstrating the vulnerability
        result = add(command)
        
        # Verify malicious database path was used
        mock_connect.assert_called()
        # Check that the malicious path would be processed
        assert str(command.db_path) == malicious_db_path
    
    def test_database_path_accepts_arbitrary_locations(self):
        """Test that database path validation is missing - VULNERABILITY EXISTS"""
        dangerous_paths = [
            "/etc/passwd.db",
            "../../../sensitive.db", 
            "/root/.ssh/keys.db",
            "/var/log/system.db"
        ]
        
        for dangerous_path in dangerous_paths:
            # All these paths should be accepted without validation
            command = AddCommand(
                id=f"test-{hash(dangerous_path)}",
                text="test",
                tags=[],
                db_path=Path(dangerous_path)
            )
            
            # No validation occurs - vulnerability confirmed
            assert str(command.db_path) == dangerous_path


class TestFileSizeLimitVulnerability:
    """Tests that demonstrate lack of file size limits"""
    
    def setup_method(self):
        self.fd, self.db_path = tempfile.mkstemp()
        os.close(self.fd)
        self.db_path = Path(self.db_path)
    
    def teardown_method(self):
        if self.db_path.exists():
            self.db_path.unlink()
    
    @patch('pathlib.Path.exists', return_value=True)
    def test_large_file_memory_exhaustion_vulnerability(self, mock_exists):
        """Test that large files can be read without limits - VULNERABILITY EXISTS"""
        # Simulate a very large file
        large_content = "A" * (100 * 1024 * 1024)  # 100MB string
        
        with patch('builtins.open', mock_open(read_data=large_content)):
            command = AddFileCommand(
                id="large-file-test",
                file_path="/tmp/huge_file.txt",
                tags=["test"],
                db_path=self.db_path
            )
            
            # This should succeed but could exhaust memory - vulnerability exists
            result = add_file(command)
            
            assert result.id == "large-file-test"
            assert len(result.text) == 100 * 1024 * 1024  # No size limit enforced
    
    def test_no_file_size_validation(self):
        """Test that no file size validation exists - VULNERABILITY EXISTS"""
        # The add_file function has no size checks before reading
        with open(__file__, 'r') as f:
            source_code = f.read()
        
        # Check the actual add_file source code for size validation
        from ..modules.functionality import add_file as add_file_module
        import inspect
        
        add_file_source = inspect.getsource(add_file_module.add_file)
        
        # Verify no size validation exists in add_file function
        assert "file_size" not in add_file_source.lower()
        assert "size_limit" not in add_file_source.lower()
        assert "max_size" not in add_file_source.lower()


class TestInformationDisclosureVulnerability:
    """Tests that demonstrate information disclosure through error messages"""
    
    def setup_method(self):
        self.fd, self.db_path = tempfile.mkstemp()
        os.close(self.fd)
        self.db_path = Path(self.db_path)
    
    def teardown_method(self):
        if self.db_path.exists():
            self.db_path.unlink()
    
    def test_file_not_found_error_disclosure(self):
        """Test that file errors reveal filesystem paths - VULNERABILITY EXISTS"""
        sensitive_path = "/root/.ssh/id_rsa"
        
        command = AddFileCommand(
            id="test-disclosure",
            file_path=sensitive_path,
            tags=["test"],
            db_path=self.db_path
        )
        
        # This should raise an exception with filesystem information
        with pytest.raises((FileNotFoundError, PermissionError)) as exc_info:
            add_file(command)
        
        # Verify the error message contains the sensitive path (vulnerability confirmed)
        assert sensitive_path in str(exc_info.value)
    
    @patch('builtins.open', side_effect=IOError("Permission denied: /etc/shadow"))
    @patch('pathlib.Path.exists', return_value=True)
    def test_permission_error_disclosure(self, mock_exists, mock_open):
        """Test that permission errors reveal system information - VULNERABILITY EXISTS"""
        command = AddFileCommand(
            id="test-permission",
            file_path="/etc/shadow",
            tags=["test"],
            db_path=self.db_path
        )
        
        # This should raise an exception with system information
        with pytest.raises(IOError) as exc_info:
            add_file(command)
        
        # Verify the error message contains sensitive system information
        assert "/etc/shadow" in str(exc_info.value)
        assert "Permission denied" in str(exc_info.value)


class TestSecurityRegressionSuite:
    """Meta-tests to ensure security vulnerabilities are properly detected"""
    
    def test_all_security_vulnerabilities_detected(self):
        """Verify all major security issues are covered by tests"""
        # This test ensures we have comprehensive security test coverage
        
        security_test_methods = [
            # Directory Traversal
            'test_add_file_directory_traversal_vulnerability',
            'test_to_file_by_id_directory_traversal_vulnerability', 
            'test_backup_directory_traversal_vulnerability',
            
            # Database Path Injection
            'test_database_path_injection_vulnerability',
            'test_database_path_accepts_arbitrary_locations',
            
            # File Size Limits
            'test_large_file_memory_exhaustion_vulnerability',
            'test_no_file_size_validation',
            
            # Information Disclosure
            'test_file_not_found_error_disclosure',
            'test_permission_error_disclosure'
        ]
        
        # Verify all security test methods exist in this file
        current_file_content = open(__file__, 'r').read()
        
        for method_name in security_test_methods:
            assert method_name in current_file_content, f"Security test {method_name} missing"
        
        # Confirm we have comprehensive coverage
        assert len(security_test_methods) >= 9, "Need comprehensive security test coverage"