# Python Development Instructions

## Project Overview
This project follows modern Python best practices with emphasis on clean, maintainable, and well-tested code.

## Code Style & Formatting
- **Follow PEP 8** style guidelines strictly
- Use **4 spaces** for indentation (no tabs)
- Maximum line length of **88 characters** (Black formatter standard)
- Use **double quotes** for strings unless single quotes avoid escaping
- Import organization: standard library → third-party → local imports

## Type Hints & Documentation
- **Always use type hints** for function parameters and return values
- Use `from __future__ import annotations` for forward references
- Include **docstrings** for all public functions, classes, and modules using Google style format:

```python
def calculate_area(radius: float) -> float:
    """Calculate the area of a circle.
    
    Args:
        radius: The radius of the circle in meters.
        
    Returns:
        The area of the circle in square meters.
        
    Raises:
        ValueError: If radius is negative.
    """
    if radius < 0:
        raise ValueError("Radius must be non-negative")
    return math.pi * radius ** 2
```

## Code Organization
- Use the **src/ layout** for packages:
  ```
  project/
  ├── src/
  │   └── mypackage/
  │       ├── __init__.py
  │       ├── main.py
  │       └── utils.py
  ├── tests/
  ├── requirements.txt
  └── pyproject.toml
  ```
- **One class per file** for complex classes
- Group related functions in modules
- Use `__init__.py` to control public API

## Error Handling
- Use **specific exception types** rather than bare `except:`
- Create **custom exceptions** for domain-specific errors
- Always include meaningful error messages
- Use logging instead of print statements for debugging

```python
import logging

logger = logging.getLogger(__name__)

def process_data(data: list[str]) -> list[int]:
    try:
        return [int(item) for item in data]
    except ValueError as e:
        logger.error(f"Invalid data format: {e}")
        raise DataProcessingError(f"Cannot convert data to integers: {e}")
```

## Testing Requirements
- Use **pytest** as the testing framework
- Aim for **>90% test coverage**
- Write tests for both happy path and edge cases
- Use descriptive test function names:

```python
def test_calculate_area_with_positive_radius_returns_correct_value():
    # Arrange
    radius = 5.0
    expected_area = math.pi * 25
    
    # Act
    result = calculate_area(radius)
    
    # Assert
    assert abs(result - expected_area) < 1e-10
```

## Dependencies & Environment
- Use **virtual environments** (venv or conda)
- Pin dependencies with **specific versions** in requirements.txt
- Use **pyproject.toml** for project configuration
- Include **pre-commit hooks** for code quality

## Performance & Best Practices
- Use **list/dict comprehensions** over loops where appropriate
- Prefer **pathlib** over os.path for file operations
- Use **context managers** (with statements) for resource management
- Avoid global variables; use dependency injection instead

```python
from pathlib import Path
from typing import Protocol

class DataProcessor(Protocol):
    def process(self, data: str) -> dict: ...

def load_config(config_path: Path, processor: DataProcessor) -> dict:
    with config_path.open() as file:
        raw_data = file.read()
    return processor.process(raw_data)
```

## Security Considerations
- **Never hardcode** secrets or credentials
- Use environment variables for configuration
- Validate and sanitize all user inputs
- Use **secrets** module for cryptographically secure random values

## Example Code Structure
```python
"""Module for processing user data.

This module provides utilities for validating and transforming
user input data according to business rules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class User:
    """Represents a user in the system."""
    
    name: str
    email: str
    age: Optional[int] = None
    
    def __post_init__(self) -> None:
        """Validate user data after initialization."""
        if not self.email or "@" not in self.email:
            raise ValueError("Invalid email address")
        
    def is_adult(self) -> bool:
        """Check if the user is an adult (18+)."""
        return self.age is not None and self.age >= 18


def create_user(name: str, email: str, age: Optional[int] = None) -> User:
    """Create a new user with validation.
    
    Args:
        name: The user's full name.
        email: The user's email address.
        age: The user's age in years.
        
    Returns:
        A validated User instance.
        
    Raises:
        ValueError: If the provided data is invalid.
    """
    try:
        return User(name=name, email=email, age=age)
    except ValueError as e:
        logger.error(f"Failed to create user: {e}")
        raise
```

## Tools & Automation
- Use **Black** for code formatting
- Use **isort** for import sorting
- Use **mypy** for static type checking
- Use **flake8** or **ruff** for linting
- Set up **GitHub Actions** or similar for CI/CD

## Git Commit Messages
- Use conventional commit format: `type(scope): description`
- Examples:
  - `feat: add user authentication system`
  - `fix: handle edge case in data validation`
  - `docs: update API documentation`
  - `test: add integration tests for user service`
