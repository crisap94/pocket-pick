import sqlite3
import uuid
import json
from datetime import datetime
from pathlib import Path
import logging
from ..data_types import AddFileCommand, PocketItem
from ..init_db import init_db, normalize_tags
from ..security import PathValidator, FileSizeValidator, SecurityError, sanitize_error_message

logger = logging.getLogger(__name__)

def add_file(command: AddFileCommand) -> PocketItem:
    """
    Add a new item to the pocket pick database from a file
    
    Args:
        command: AddFileCommand with id, file_path, tags and db_path
        
    Returns:
        PocketItem: The newly created item
        
    Raises:
        sqlite3.IntegrityError: If an item with the same ID already exists
        SecurityError: If file path or database path is invalid
        FileNotFoundError: If the specified file doesn't exist
    """
    # Validate database path
    try:
        validated_db_path = PathValidator.validate_db_path(command.db_path)
    except SecurityError as e:
        logger.error(f"Database path validation failed: {e}")
        raise SecurityError(sanitize_error_message(str(e)))
    
    # Validate and secure file path
    try:
        validated_file_path = PathValidator.validate_file_path(command.file_path)
    except SecurityError as e:
        logger.error(f"File path validation failed: {e}")
        raise SecurityError(sanitize_error_message(str(e)))
    
    # Validate file size before reading
    try:
        FileSizeValidator.validate_file_size(validated_file_path)
    except SecurityError as e:
        logger.error(f"File size validation failed: {e}")
        raise SecurityError(sanitize_error_message(str(e)))
    
    # Read the file content
    try:
        if not validated_file_path.exists():
            raise FileNotFoundError("Specified file does not exist")
        
        with open(validated_file_path, 'r', encoding='utf-8') as f:
            text = f.read()
    except FileNotFoundError:
        # Re-raise FileNotFoundError for backward compatibility
        raise
    except Exception as e:
        logger.error(f"Error reading file: {sanitize_error_message(str(e))}")
        raise SecurityError("Failed to read file")
    
    # Normalize tags
    normalized_tags = normalize_tags(command.tags)
    
    # Use the provided ID
    item_id = command.id
    
    # Get current timestamp
    timestamp = datetime.now()
    
    # Connect to database using validated path
    db = init_db(validated_db_path)
    
    try:
        # Serialize tags to JSON
        tags_json = json.dumps(normalized_tags)
        
        # Insert item
        try:
            db.execute(
                "INSERT INTO POCKET_PICK (id, created, text, tags) VALUES (?, ?, ?, ?)",
                (item_id, timestamp.isoformat(), text, tags_json)
            )
            
            # Commit transaction
            db.commit()
            
            # Return created item
            return PocketItem(
                id=item_id,
                created=timestamp,
                text=text,
                tags=normalized_tags
            )
        except sqlite3.IntegrityError:
            logger.error(f"Item with ID {item_id} already exists")
            raise sqlite3.IntegrityError(f"Item with ID {item_id} already exists")
    except Exception as e:
        logger.error(f"Error adding item from file: {e}")
        raise
    finally:
        db.close()