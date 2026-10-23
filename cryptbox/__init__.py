"""
cryptbox-cli
Zero-Trust Authenticated File & Folder Vault using AES-256-GCM
"""

__version__ = "0.1.0"
__author__ = "Zephyrus Labs"
__maintainer__ = "Shubham Sharma"
__email__ = "zephyrus.labs@gmail.com"
__developer_email__ = "sharmashubham25962@gmail.com"

from .core import lock_path, unlock_vault, inspect_vault, AuthenticationError

__all__ = [
    "lock_path",
    "unlock_vault",
    "inspect_vault",
    "AuthenticationError",
    "__version__",
    "__author__",
    "__maintainer__",
    "__email__",
    "__developer_email__",
]
