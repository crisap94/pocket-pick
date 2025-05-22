import sqlite3
import shutil
import logging
from ..data_types import BackupCommand
from ..init_db import init_db
from ..security import PathValidator, SecurityError, sanitize_error_message

logger = logging.getLogger(__name__)

def backup(command: BackupCommand) -> bool:
    """
    Backup the pocket pick database to a specified location
    
    Args:
        command: BackupCommand with backup destination path
        
    Returns:
        bool: True if backup was successful, False otherwise
        
    Raises:
        SecurityError: If database path or backup path is invalid
    """
    try:
        # Validate database path
        try:
            validated_db_path = PathValidator.validate_db_path(command.db_path)
        except SecurityError as e:
            logger.error(f"Database path validation failed: {e}")
            raise SecurityError(sanitize_error_message(str(e)))
        
        # Validate backup path (also treat as database path since it's a .db file)
        try:
            validated_backup_path = PathValidator.validate_db_path(command.backup_path)
        except SecurityError as e:
            logger.error(f"Backup path validation failed: {e}")
            raise SecurityError(sanitize_error_message(str(e)))
        
        # Make sure source DB exists by initializing it if needed
        db = init_db(validated_db_path)
        db.close()
        
        # Create parent directories if they don't exist
        validated_backup_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Copy the database file to the backup location
        shutil.copy2(validated_db_path, validated_backup_path)
        
        # Verify the backup file exists
        if validated_backup_path.exists():
            logger.info(f"Backup created successfully")
            return True
        else:
            logger.error(f"Backup file verification failed")
            return False
    except SecurityError:
        # Re-raise security errors
        raise
    except Exception as e:
        logger.error(f"Error creating backup: {sanitize_error_message(str(e))}")
        return False