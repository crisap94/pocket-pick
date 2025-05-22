import sqlite3
import uuid
import json
from datetime import datetime
from pathlib import Path
import logging
from ..data_types import AddCommand, PocketItem
from ..init_db import init_db, normalize_tags
from ..security import PathValidator, SecurityError, sanitize_error_message

logger = logging.getLogger(__name__)

def add(command: AddCommand) -> PocketItem:
    """
    Add a new item to the pocket pick database
    
    Args:
        command: AddCommand with id, text, tags and db_path
        
    Returns:
        PocketItem: The newly created item
        
    Raises:
        sqlite3.IntegrityError: If an item with the same ID already exists
        SecurityError: If database path is invalid
    """
    # Validate database path
    try:
        validated_db_path = PathValidator.validate_db_path(command.db_path)
    except SecurityError as e:
        logger.error(f"Database path validation failed: {e}")
        raise SecurityError(sanitize_error_message(str(e)))
    
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
                (item_id, timestamp.isoformat(), command.text, tags_json)
            )
            
            # Commit transaction
            db.commit()
            
            # Return created item
            return PocketItem(
                id=item_id,
                created=timestamp,
                text=command.text,
                tags=normalized_tags
            )
        except sqlite3.IntegrityError:
            logger.error(f"Item with ID {item_id} already exists")
            raise sqlite3.IntegrityError(f"Item with ID {item_id} already exists")
    except Exception as e:
        logger.error(f"Error adding item: {e}")
        raise
    finally:
        db.close()