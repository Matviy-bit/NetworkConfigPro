"""Secure vault for storing sensitive configuration data."""

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureVault:
    """Encrypted storage for sensitive network configuration data.

    Uses Fernet symmetric encryption with PBKDF2 key derivation.
    All data is encrypted at rest and only decrypted in memory when needed.
    """

    SALT_SIZE = 16
    ITERATIONS = 480000  # OWASP recommended minimum for PBKDF2-SHA256

    def __init__(self, vault_path: Optional[Path] = None):
        """Initialize the secure vault.

        Args:
            vault_path: Path to the vault file. Defaults to user's app data directory.
        """
        if vault_path is None:
            app_dir = Path.home() / ".netconfigpro"
            app_dir.mkdir(mode=0o700, exist_ok=True)
            self.vault_path = app_dir / "vault.enc"
        else:
            self.vault_path = Path(vault_path)

        self._fernet: Optional[Fernet] = None
        self._data: dict[str, Any] = {}
        self._is_unlocked = False

    @property
    def is_locked(self) -> bool:
        """Check if vault is locked."""
        return not self._is_unlocked

    @property
    def exists(self) -> bool:
        """Check if vault file exists."""
        return self.vault_path.exists()

    def create(self, master_password: str) -> bool:
        """Create a new vault with the given master password.

        Args:
            master_password: Master password for the vault

        Returns:
            True if vault was created successfully
        """
        if self.exists:
            raise ValueError("Vault already exists. Use unlock() or delete first.")

        if len(master_password) < 8:
            raise ValueError("Master password must be at least 8 characters")

        # Generate salt
        salt = secrets.token_bytes(self.SALT_SIZE)

        # Derive key from password
        self._fernet = self._derive_key(master_password, salt)

        # Initialize empty vault data
        self._data = {
            "credentials": {},
            "variables": {},
            "templates": {},
        }

        # Save vault with salt
        self._save(salt)
        self._is_unlocked = True

        return True

    def unlock(self, master_password: str) -> bool:
        """Unlock an existing vault.

        Args:
            master_password: Master password for the vault

        Returns:
            True if vault was unlocked successfully

        Raises:
            ValueError: If vault doesn't exist or password is wrong
        """
        if not self.exists:
            raise ValueError("Vault does not exist. Create one first.")

        try:
            with open(self.vault_path, "rb") as f:
                encrypted_data = f.read()

            # Extract salt (first SALT_SIZE bytes)
            salt = encrypted_data[:self.SALT_SIZE]
            ciphertext = encrypted_data[self.SALT_SIZE:]

            # Derive key and decrypt
            self._fernet = self._derive_key(master_password, salt)
            decrypted = self._fernet.decrypt(ciphertext)
            self._data = json.loads(decrypted.decode("utf-8"))
            self._is_unlocked = True

            return True

        except InvalidToken:
            self._fernet = None
            self._is_unlocked = False
            raise ValueError("Invalid master password")
        except Exception as e:
            self._fernet = None
            self._is_unlocked = False
            raise ValueError(f"Failed to unlock vault: {str(e)}")

    def lock(self) -> None:
        """Lock the vault, clearing all decrypted data from memory."""
        self._fernet = None
        self._data = {}
        self._is_unlocked = False

    def change_password(self, old_password: str, new_password: str) -> bool:
        """Change the vault master password.

        Args:
            old_password: Current master password
            new_password: New master password

        Returns:
            True if password was changed successfully
        """
        if len(new_password) < 8:
            raise ValueError("New password must be at least 8 characters")

        # Unlock with old password to verify it
        self.unlock(old_password)

        # Generate new salt and re-encrypt with new password
        salt = secrets.token_bytes(self.SALT_SIZE)
        self._fernet = self._derive_key(new_password, salt)
        self._save(salt)

        return True

    def store_credential(self, name: str, username: str, password: str, description: str = "") -> None:
        """Store a credential securely.

        Args:
            name: Unique identifier for the credential
            username: Username
            password: Password
            description: Optional description
        """
        self._ensure_unlocked()

        self._data.setdefault("credentials", {})[name] = {
            "username": username,
            "password": password,
            "description": description,
        }
        self._save_current()

    def get_credential(self, name: str) -> Optional[dict[str, str]]:
        """Retrieve a credential.

        Args:
            name: Credential identifier

        Returns:
            Credential dict or None if not found
        """
        self._ensure_unlocked()
        return self._data.get("credentials", {}).get(name)

    def delete_credential(self, name: str) -> bool:
        """Delete a credential.

        Args:
            name: Credential identifier

        Returns:
            True if credential was deleted
        """
        self._ensure_unlocked()

        if name in self._data.get("credentials", {}):
            del self._data["credentials"][name]
            self._save_current()
            return True
        return False

    def list_credentials(self) -> list[str]:
        """List all stored credential names.

        Returns:
            List of credential identifiers
        """
        self._ensure_unlocked()
        return list(self._data.get("credentials", {}).keys())

    def store_variable(self, name: str, value: str, is_secret: bool = False) -> None:
        """Store a template variable.

        Args:
            name: Variable name
            value: Variable value
            is_secret: Whether this is a secret value (affects display)
        """
        self._ensure_unlocked()

        self._data.setdefault("variables", {})[name] = {
            "value": value,
            "is_secret": is_secret,
        }
        self._save_current()

    def get_variable(self, name: str) -> Optional[dict[str, Any]]:
        """Retrieve a variable.

        Args:
            name: Variable name

        Returns:
            Variable dict or None if not found
        """
        self._ensure_unlocked()
        return self._data.get("variables", {}).get(name)

    def get_all_variables(self) -> dict[str, Any]:
        """Get all variables.

        Returns:
            Dict of all variables
        """
        self._ensure_unlocked()
        return self._data.get("variables", {}).copy()

    def delete_variable(self, name: str) -> bool:
        """Delete a variable.

        Args:
            name: Variable name

        Returns:
            True if variable was deleted
        """
        self._ensure_unlocked()

        if name in self._data.get("variables", {}):
            del self._data["variables"][name]
            self._save_current()
            return True
        return False

    def store_template(self, name: str, content: str, vendor: str) -> None:
        """Store a custom template.

        Args:
            name: Template name
            content: Template content
            vendor: Target vendor
        """
        self._ensure_unlocked()

        self._data.setdefault("templates", {})[name] = {
            "content": content,
            "vendor": vendor,
        }
        self._save_current()

    def get_template(self, name: str) -> Optional[dict[str, str]]:
        """Retrieve a template.

        Args:
            name: Template name

        Returns:
            Template dict or None if not found
        """
        self._ensure_unlocked()
        return self._data.get("templates", {}).get(name)

    def list_templates(self) -> list[str]:
        """List all stored template names.

        Returns:
            List of template names
        """
        self._ensure_unlocked()
        return list(self._data.get("templates", {}).keys())

    def delete_template(self, name: str) -> bool:
        """Delete a template.

        Args:
            name: Template name

        Returns:
            True if template was deleted
        """
        self._ensure_unlocked()

        if name in self._data.get("templates", {}):
            del self._data["templates"][name]
            self._save_current()
            return True
        return False

    def export_non_sensitive(self) -> dict[str, Any]:
        """Export non-sensitive data (for backup/sharing).

        Returns:
            Dict with non-sensitive data only
        """
        self._ensure_unlocked()

        result = {
            "variables": {},
            "templates": self._data.get("templates", {}),
        }

        # Only export non-secret variables
        for name, var in self._data.get("variables", {}).items():
            if not var.get("is_secret", False):
                result["variables"][name] = var

        return result

    def _derive_key(self, password: str, salt: bytes) -> Fernet:
        """Derive encryption key from password using PBKDF2.

        Args:
            password: User password
            salt: Random salt

        Returns:
            Fernet instance with derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def _save(self, salt: bytes) -> None:
        """Save vault data to disk.

        Args:
            salt: Salt used for key derivation
        """
        if not self._fernet:
            raise ValueError("Vault not unlocked")

        plaintext = json.dumps(self._data).encode("utf-8")
        ciphertext = self._fernet.encrypt(plaintext)

        # Write salt + ciphertext atomically
        temp_path = self.vault_path.with_suffix(".tmp")
        with open(temp_path, "wb") as f:
            f.write(salt + ciphertext)

        # Atomic rename
        temp_path.replace(self.vault_path)

        # Set restrictive permissions
        os.chmod(self.vault_path, 0o600)

    def _save_current(self) -> None:
        """Save vault data using current salt."""
        if not self._fernet or not self.exists:
            raise ValueError("Vault not properly initialized")

        # Read current salt
        with open(self.vault_path, "rb") as f:
            salt = f.read(self.SALT_SIZE)

        self._save(salt)

    def _ensure_unlocked(self) -> None:
        """Raise error if vault is locked."""
        if self.is_locked:
            raise ValueError("Vault is locked. Call unlock() first.")


class MemoryVault:
    """In-memory vault for session-only storage (never persisted to disk).

    Useful for temporarily storing sensitive data during a session.
    """

    def __init__(self):
        """Initialize the memory vault."""
        self._data: dict[str, str] = {}

    def store(self, key: str, value: str) -> None:
        """Store a value."""
        self._data[key] = value

    def get(self, key: str) -> Optional[str]:
        """Retrieve a value."""
        return self._data.get(key)

    def delete(self, key: str) -> bool:
        """Delete a value."""
        if key in self._data:
            del self._data[key]
            return True
        return False

    def clear(self) -> None:
        """Clear all stored data."""
        self._data.clear()

    def list_keys(self) -> list[str]:
        """List all keys."""
        return list(self._data.keys())
