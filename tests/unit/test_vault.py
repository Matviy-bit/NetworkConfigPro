"""Tests for secure vault."""

import os
import tempfile
from pathlib import Path

import pytest

from src.security.vault import MemoryVault, SecureVault


@pytest.fixture
def temp_vault_path():
    """Create a temporary vault path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_vault.enc"


@pytest.fixture
def vault(temp_vault_path):
    """Create a vault instance with temp path."""
    return SecureVault(vault_path=temp_vault_path)


@pytest.fixture
def unlocked_vault(vault):
    """Create and unlock a vault."""
    vault.create("TestPassword123!")
    return vault


class TestSecureVault:
    """Tests for SecureVault class."""

    def test_vault_not_exists_initially(self, vault):
        """Test vault doesn't exist initially."""
        assert vault.exists is False
        assert vault.is_locked is True

    def test_create_vault(self, vault):
        """Test creating a new vault."""
        result = vault.create("SecurePassword123!")

        assert result is True
        assert vault.exists is True
        assert vault.is_locked is False

    def test_create_vault_weak_password(self, vault):
        """Test creating vault with weak password fails."""
        with pytest.raises(ValueError, match="at least 8 characters"):
            vault.create("short")

    def test_create_vault_already_exists(self, unlocked_vault):
        """Test creating vault when one exists fails."""
        with pytest.raises(ValueError, match="already exists"):
            unlocked_vault.create("AnotherPassword123!")

    def test_lock_vault(self, unlocked_vault):
        """Test locking the vault."""
        unlocked_vault.lock()

        assert unlocked_vault.is_locked is True

    def test_unlock_vault(self, vault):
        """Test unlocking the vault."""
        vault.create("TestPassword123!")
        vault.lock()

        result = vault.unlock("TestPassword123!")

        assert result is True
        assert vault.is_locked is False

    def test_unlock_vault_wrong_password(self, vault):
        """Test unlocking with wrong password fails."""
        vault.create("CorrectPassword123!")
        vault.lock()

        with pytest.raises(ValueError, match="Invalid master password"):
            vault.unlock("WrongPassword123!")

    def test_unlock_nonexistent_vault(self, vault):
        """Test unlocking nonexistent vault fails."""
        with pytest.raises(ValueError, match="does not exist"):
            vault.unlock("AnyPassword123!")

    def test_change_password(self, vault):
        """Test changing vault password."""
        vault.create("OldPassword123!")
        vault.lock()

        result = vault.change_password("OldPassword123!", "NewPassword123!")

        assert result is True

        # Verify old password no longer works
        vault.lock()
        with pytest.raises(ValueError):
            vault.unlock("OldPassword123!")

        # Verify new password works
        vault.unlock("NewPassword123!")
        assert vault.is_locked is False


class TestCredentialStorage:
    """Tests for credential storage."""

    def test_store_credential(self, unlocked_vault):
        """Test storing a credential."""
        unlocked_vault.store_credential(
            name="router-admin",
            username="admin",
            password="secret123",
            description="Admin account",
        )

        creds = unlocked_vault.list_credentials()
        assert "router-admin" in creds

    def test_get_credential(self, unlocked_vault):
        """Test retrieving a credential."""
        unlocked_vault.store_credential(
            name="test-cred",
            username="testuser",
            password="testpass",
            description="Test credential",
        )

        cred = unlocked_vault.get_credential("test-cred")

        assert cred is not None
        assert cred["username"] == "testuser"
        assert cred["password"] == "testpass"
        assert cred["description"] == "Test credential"

    def test_get_nonexistent_credential(self, unlocked_vault):
        """Test getting nonexistent credential returns None."""
        cred = unlocked_vault.get_credential("nonexistent")

        assert cred is None

    def test_delete_credential(self, unlocked_vault):
        """Test deleting a credential."""
        unlocked_vault.store_credential(
            name="to-delete",
            username="user",
            password="pass",
        )

        result = unlocked_vault.delete_credential("to-delete")

        assert result is True
        assert unlocked_vault.get_credential("to-delete") is None

    def test_delete_nonexistent_credential(self, unlocked_vault):
        """Test deleting nonexistent credential returns False."""
        result = unlocked_vault.delete_credential("nonexistent")

        assert result is False

    def test_credentials_persist_after_lock_unlock(self, vault):
        """Test credentials persist across lock/unlock."""
        vault.create("TestPassword123!")

        vault.store_credential(
            name="persist-test",
            username="user",
            password="pass",
        )

        vault.lock()
        vault.unlock("TestPassword123!")

        cred = vault.get_credential("persist-test")
        assert cred is not None
        assert cred["username"] == "user"

    def test_operations_require_unlock(self, vault):
        """Test operations fail when vault is locked."""
        vault.create("TestPassword123!")
        vault.lock()

        with pytest.raises(ValueError, match="locked"):
            vault.store_credential("name", "user", "pass")

        with pytest.raises(ValueError, match="locked"):
            vault.get_credential("name")


class TestVariableStorage:
    """Tests for variable storage."""

    def test_store_variable(self, unlocked_vault):
        """Test storing a variable."""
        unlocked_vault.store_variable("snmp_community", "public123")

        var = unlocked_vault.get_variable("snmp_community")
        assert var is not None
        assert var["value"] == "public123"

    def test_store_secret_variable(self, unlocked_vault):
        """Test storing a secret variable."""
        unlocked_vault.store_variable("api_key", "secret-key", is_secret=True)

        var = unlocked_vault.get_variable("api_key")
        assert var["is_secret"] is True

    def test_get_all_variables(self, unlocked_vault):
        """Test getting all variables."""
        unlocked_vault.store_variable("var1", "value1")
        unlocked_vault.store_variable("var2", "value2")

        variables = unlocked_vault.get_all_variables()

        assert len(variables) == 2
        assert "var1" in variables
        assert "var2" in variables

    def test_delete_variable(self, unlocked_vault):
        """Test deleting a variable."""
        unlocked_vault.store_variable("to-delete", "value")

        result = unlocked_vault.delete_variable("to-delete")

        assert result is True
        assert unlocked_vault.get_variable("to-delete") is None


class TestTemplateStorage:
    """Tests for template storage."""

    def test_store_template(self, unlocked_vault):
        """Test storing a template."""
        unlocked_vault.store_template(
            name="my-template",
            content="hostname {{ hostname }}",
            vendor="cisco_ios",
        )

        templates = unlocked_vault.list_templates()
        assert "my-template" in templates

    def test_get_template(self, unlocked_vault):
        """Test retrieving a template."""
        unlocked_vault.store_template(
            name="test-template",
            content="interface {{ interface }}",
            vendor="cisco_ios",
        )

        template = unlocked_vault.get_template("test-template")

        assert template is not None
        assert template["content"] == "interface {{ interface }}"
        assert template["vendor"] == "cisco_ios"

    def test_delete_template(self, unlocked_vault):
        """Test deleting a template."""
        unlocked_vault.store_template("to-delete", "content", "vendor")

        result = unlocked_vault.delete_template("to-delete")

        assert result is True
        assert unlocked_vault.get_template("to-delete") is None


class TestExportFunctionality:
    """Tests for export functionality."""

    def test_export_non_sensitive(self, unlocked_vault):
        """Test exporting non-sensitive data."""
        # Store various data
        unlocked_vault.store_credential("cred1", "user", "pass")
        unlocked_vault.store_variable("public_var", "public", is_secret=False)
        unlocked_vault.store_variable("secret_var", "secret", is_secret=True)
        unlocked_vault.store_template("template1", "content", "vendor")

        exported = unlocked_vault.export_non_sensitive()

        # Credentials should not be exported
        assert "credentials" not in exported or len(exported.get("credentials", {})) == 0

        # Non-secret variables should be exported
        assert "public_var" in exported["variables"]

        # Secret variables should not be exported
        assert "secret_var" not in exported["variables"]

        # Templates should be exported
        assert "template1" in exported["templates"]


class TestFilePermissions:
    """Tests for file permission handling."""

    def test_vault_file_permissions(self, vault):
        """Test vault file has restrictive permissions."""
        vault.create("TestPassword123!")

        # Check file permissions (Unix-like systems only)
        if os.name != "nt":
            mode = os.stat(vault.vault_path).st_mode & 0o777
            assert mode == 0o600


class TestMemoryVault:
    """Tests for MemoryVault class."""

    def test_store_and_get(self):
        """Test storing and retrieving values."""
        vault = MemoryVault()

        vault.store("key1", "value1")
        result = vault.get("key1")

        assert result == "value1"

    def test_get_nonexistent(self):
        """Test getting nonexistent key returns None."""
        vault = MemoryVault()

        result = vault.get("nonexistent")

        assert result is None

    def test_delete(self):
        """Test deleting a value."""
        vault = MemoryVault()
        vault.store("key", "value")

        result = vault.delete("key")

        assert result is True
        assert vault.get("key") is None

    def test_delete_nonexistent(self):
        """Test deleting nonexistent returns False."""
        vault = MemoryVault()

        result = vault.delete("nonexistent")

        assert result is False

    def test_clear(self):
        """Test clearing all values."""
        vault = MemoryVault()
        vault.store("key1", "value1")
        vault.store("key2", "value2")

        vault.clear()

        assert len(vault.list_keys()) == 0

    def test_list_keys(self):
        """Test listing all keys."""
        vault = MemoryVault()
        vault.store("key1", "value1")
        vault.store("key2", "value2")

        keys = vault.list_keys()

        assert "key1" in keys
        assert "key2" in keys
