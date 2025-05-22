from pathlib import Path
import logging
import os
from ..data_types import ToFileByIdCommand, PocketItem
from .get import get
from .get import GetCommand
from ..security import PathValidator, SecurityError, sanitize_error_message

logger = logging.getLogger(__name__)

def to_file_by_id(command: ToFileByIdCommand) -> bool:
    """
    Write pocket pick content with given ID to the specified file
    
    Args:
        command: ToFileByIdCommand with id, output_file_path and db_path
        
    Returns:
        bool: True if successful, False otherwise
        
    Raises:
        SecurityError: If file path or database path is invalid
    """
    try:
        # Validate database path
        try:
            validated_db_path = PathValidator.validate_db_path(command.db_path)
        except SecurityError as e:
            logger.error(f"Database path validation failed: {e}")
            raise SecurityError(sanitize_error_message(str(e)))
        
        # Validate output file path
        try:
            validated_output_path = PathValidator.validate_file_path(command.output_file_path_abs)
        except SecurityError as e:
            logger.error(f"Output path validation failed: {e}")
            raise SecurityError(sanitize_error_message(str(e)))
        
        # First get the item from the database
        get_command = GetCommand(
            id=command.id,
            db_path=validated_db_path
        )
        
        item = get(get_command)
        
        if not item:
            logger.error(f"Item not found")
            return False
        
        # Ensure parent directory exists (using validated path)
        validated_output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write content to file
        with open(validated_output_path, 'w', encoding='utf-8') as f:
            f.write(item.text)
        
        return True
    except SecurityError:
        # Re-raise security errors
        raise
    except Exception as e:
        logger.error(f"Error writing to file: {sanitize_error_message(str(e))}")
        return False