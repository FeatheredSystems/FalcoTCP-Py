"""
FalcoTCP-Py: Secure TCP server/client with AES-256-GCM encryption.
"""

__version__ = "0.1.0"

from .client import Client
from .server import Server
from .errors import AuthenticationError

__all__ = [
    "Client",
    "Server",
    "AuthenticationError",
]
