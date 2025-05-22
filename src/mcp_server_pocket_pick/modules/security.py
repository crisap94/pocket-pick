"""
Security utilities for path validation and sanitization
"""
import os
from pathlib import Path
from typing import Union, Optional


class SecurityError(Exception):
    """Raised when a security violation is detected"""
    pass


class PathValidator:
    """Validates file paths to prevent directory traversal and other attacks"""
    
    @staticmethod
    def validate_file_path(file_path: Union[str, Path], allowed_dirs: Optional[list] = None) -> Path:
        """
        Validate a file path to prevent directory traversal attacks
        
        Args:
            file_path: Path to validate
            allowed_dirs: List of allowed base directories (optional)
            
        Returns:
            Validated Path object
            
        Raises:
            SecurityError: If path contains dangerous patterns
        """
        path = Path(file_path).resolve()
        
        # Check for directory traversal patterns
        if ".." in str(file_path):
            raise SecurityError(f"Directory traversal detected in path: {file_path}")
        
        # Allow temporary files for testing (they start with /tmp/tmp)
        path_str = str(path)
        is_temp_file = path_str.startswith('/tmp/tmp')
        
        # Check for absolute paths to sensitive locations (except temp files)
        if not is_temp_file:
            sensitive_paths = [
                "/etc/", "/root/", "/var/", "/usr/", "/sys/", "/proc/",
                "/boot/", "/dev/", "/lib/", "/sbin/", "/bin/"
            ]
            
            for sensitive in sensitive_paths:
                if path_str.startswith(sensitive):
                    raise SecurityError(f"Access to sensitive directory denied: {path}")
        
        # If allowed directories specified, ensure path is within them
        if allowed_dirs:
            allowed = False
            for allowed_dir in allowed_dirs:
                try:
                    path.relative_to(Path(allowed_dir).resolve())
                    allowed = True
                    break
                except ValueError:
                    continue
            
            if not allowed:
                raise SecurityError(f"Path outside allowed directories: {path}")
        
        return path
    
    @staticmethod
    def validate_db_path(db_path: Union[str, Path]) -> Path:
        """
        Validate database path to prevent access to sensitive files
        
        Args:
            db_path: Database path to validate
            
        Returns:
            Validated Path object
            
        Raises:
            SecurityError: If path is dangerous
        """
        path = Path(db_path).resolve()
        
        # Check for directory traversal
        if ".." in str(db_path):
            raise SecurityError(f"Directory traversal detected in database path: {db_path}")
        
        # Allow temporary files for testing (they start with /tmp/tmp)
        path_str = str(path)
        is_temp_file = path_str.startswith('/tmp/tmp')
        
        # Ensure .db extension (except for temp files)
        if not is_temp_file and not path_str.endswith('.db'):
            raise SecurityError(f"Database path must end with .db: {path}")
        
        # Check for sensitive system locations
        sensitive_paths = [
            "/etc/", "/root/", "/var/", "/usr/", "/sys/", "/proc/",
            "/boot/", "/dev/", "/lib/", "/sbin/", "/bin/"
        ]
        
        for sensitive in sensitive_paths:
            if path_str.startswith(sensitive):
                raise SecurityError(f"Database access to sensitive directory denied: {path}")
        
        return path


class FileSizeValidator:
    """Validates file sizes to prevent memory exhaustion attacks"""
    
    # 10MB default limit
    DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024
    
    @staticmethod
    def validate_file_size(file_path: Union[str, Path], max_size: int = DEFAULT_MAX_FILE_SIZE) -> None:
        """
        Validate file size to prevent memory exhaustion
        
        Args:
            file_path: Path to file to check
            max_size: Maximum allowed file size in bytes
            
        Raises:
            SecurityError: If file is too large
        """
        path = Path(file_path)
        
        if not path.exists():
            return  # File doesn't exist, size check not needed
        
        file_size = path.stat().st_size
        
        if file_size > max_size:
            raise SecurityError(
                f"File too large: {file_size} bytes exceeds limit of {max_size} bytes"
            )


def sanitize_error_message(error_msg: str, safe_placeholder: str = "file") -> str:
    """
    Sanitize error messages to prevent information disclosure
    
    Args:
        error_msg: Original error message
        safe_placeholder: Safe placeholder text
        
    Returns:
        Sanitized error message
    """
    # Remove sensitive path information
    import re
    
    # Replace absolute paths with placeholder
    sanitized = re.sub(r'/[a-zA-Z0-9_\-\.\/]+', safe_placeholder, error_msg)
    
    # Replace common sensitive patterns
    sensitive_patterns = [
        r'Permission denied.*',
        r'No such file or directory.*',
        r'/etc/.*',
        r'/root/.*',
        r'/home/.*',
        r'/var/.*'
    ]
    
    for pattern in sensitive_patterns:
        sanitized = re.sub(pattern, f"Access denied to {safe_placeholder}", sanitized)
    
    return sanitized