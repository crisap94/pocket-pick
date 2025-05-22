from pathlib import Path
from pydantic import BaseModel, field_validator
from typing import List, Optional
from datetime import datetime
from .constants import DEFAULT_SQLITE_DATABASE_PATH


def validate_db_path(path_value):
    """Validator for database paths to prevent security vulnerabilities"""
    from .security import PathValidator, SecurityError
    try:
        return PathValidator.validate_db_path(path_value)
    except SecurityError as e:
        raise ValueError(f"Invalid database path: {e}")


def validate_file_path(path_value):
    """Validator for file paths to prevent security vulnerabilities"""
    from .security import PathValidator, SecurityError
    try:
        return PathValidator.validate_file_path(path_value)
    except SecurityError as e:
        raise ValueError(f"Invalid file path: {e}")


class AddCommand(BaseModel):
    id: str
    text: str
    tags: List[str] = []
    db_path: Path = DEFAULT_SQLITE_DATABASE_PATH
    
    @field_validator('db_path')
    @classmethod
    def validate_database_path(cls, v):
        return validate_db_path(v)


class AddFileCommand(BaseModel):
    id: str
    file_path: str
    tags: List[str] = []
    db_path: Path = DEFAULT_SQLITE_DATABASE_PATH
    
    @field_validator('db_path')
    @classmethod
    def validate_database_path(cls, v):
        return validate_db_path(v)
    
    @field_validator('file_path')
    @classmethod
    def validate_file_path_field(cls, v):
        return validate_file_path(v)


class FindCommand(BaseModel):
    text: str
    mode: str = "substr"  # substr | fts | glob | regex | exact
    limit: int = 5
    info: bool = False
    tags: List[str] = []
    db_path: Path = DEFAULT_SQLITE_DATABASE_PATH
    
    @field_validator('db_path')
    @classmethod
    def validate_database_path(cls, v):
        return validate_db_path(v)


class ListCommand(BaseModel):
    tags: List[str] = []
    limit: int = 100
    db_path: Path = DEFAULT_SQLITE_DATABASE_PATH
    
    @field_validator('db_path')
    @classmethod
    def validate_database_path(cls, v):
        return validate_db_path(v)


class ListTagsCommand(BaseModel):
    limit: int = 1000
    db_path: Path = DEFAULT_SQLITE_DATABASE_PATH
    
    @field_validator('db_path')
    @classmethod
    def validate_database_path(cls, v):
        return validate_db_path(v)


class RemoveCommand(BaseModel):
    id: str
    db_path: Path = DEFAULT_SQLITE_DATABASE_PATH
    
    @field_validator('db_path')
    @classmethod
    def validate_database_path(cls, v):
        return validate_db_path(v)


class GetCommand(BaseModel):
    id: str
    db_path: Path = DEFAULT_SQLITE_DATABASE_PATH
    
    @field_validator('db_path')
    @classmethod
    def validate_database_path(cls, v):
        return validate_db_path(v)


class BackupCommand(BaseModel):
    backup_path: Path
    db_path: Path = DEFAULT_SQLITE_DATABASE_PATH
    
    @field_validator('db_path')
    @classmethod
    def validate_database_path(cls, v):
        return validate_db_path(v)
    
    @field_validator('backup_path')
    @classmethod
    def validate_backup_path_field(cls, v):
        return validate_db_path(v)  # backup paths are also db files


class ToFileByIdCommand(BaseModel):
    id: str
    output_file_path_abs: Path
    db_path: Path = DEFAULT_SQLITE_DATABASE_PATH
    
    @field_validator('db_path')
    @classmethod
    def validate_database_path(cls, v):
        return validate_db_path(v)
    
    @field_validator('output_file_path_abs')
    @classmethod
    def validate_output_path(cls, v):
        return validate_file_path(v)


class PocketItem(BaseModel):
    id: str
    created: datetime
    text: str
    tags: List[str]


class ListIdsCommand(BaseModel):
    tags: List[str] = []
    limit: int = 100
    db_path: Path = DEFAULT_SQLITE_DATABASE_PATH
    
    @field_validator('db_path')
    @classmethod
    def validate_database_path(cls, v):
        return validate_db_path(v)
