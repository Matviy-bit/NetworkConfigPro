"""Tests for configuration validator."""

import pytest

from src.core.models import (
    ACL,
    ACLAction,
    ACLEntry,
    ACLProtocol,
    BGPConfig,
    BGPNeighbor,
    DeviceConfig,
    Interface,
    InterfaceType,
    OSPFConfig,
    OSPFNetwork,
    StaticRoute,
    Vendor,
    VLAN,
)
from src.core.validators.config_validator import (
    Category,
    ConfigValidator,
    Severity,
)


@pytest.fixture
def validator():
    """Create a validator instance."""
    return ConfigValidator()


@pytest.fixture
def valid_config():
    """Create a valid device configuration."""
    return DeviceConfig(
        hostname="valid-router",
        vendor=Vendor.CISCO_IOS,
        domain_name="example.com",
        enable_secret="StrongPassword123!",
        dns_servers=["8.8.8.8"],
        ntp_servers=["pool.ntp.org"],
        banner_motd="Authorized users only",
        interfaces=[
            Interface(
                name="Gi0/0",
                interface_type=InterfaceType.GIGABIT,
                description="WAN Link",
                ip_address="10.0.0.1",
                subnet_mask="255.255.255.0",
            ),
        ],
    )


class TestHostnameValidation:
    """Tests for hostname validation."""

    def test_valid_hostname(self, validator):
        """Test valid hostname passes validation."""
        config = DeviceConfig(hostname="router1", vendor=Vendor.CISCO_IOS)
        issues = validator.validate(config)

        hostname_errors = [i for i in issues if "hostname" in i.message.lower()
                          and i.severity == Severity.ERROR]
        assert len(hostname_errors) == 0

    def test_empty_hostname(self, validator):
        """Test empty hostname fails validation."""
        config = DeviceConfig(hostname="", vendor=Vendor.CISCO_IOS)
        issues = validator.validate(config)

        assert any(
            i.severity == Severity.ERROR and "Hostname is not configured" in i.message
            for i in issues
        )

    def test_invalid_hostname_format(self, validator):
        """Test invalid hostname format fails validation."""
        config = DeviceConfig(hostname="123-invalid", vendor=Vendor.CISCO_IOS)
        issues = validator.validate(config)

        assert any(
            i.severity == Severity.ERROR and "Invalid hostname format" in i.message
            for i in issues
        )

    def test_hostname_too_long(self, validator):
        """Test hostname over 63 chars fails validation."""
        config = DeviceConfig(hostname="a" * 64, vendor=Vendor.CISCO_IOS)
        issues = validator.validate(config)

        assert any(
            i.severity == Severity.ERROR and "too long" in i.message.lower()
            for i in issues
        )


class TestInterfaceValidation:
    """Tests for interface validation."""

    def test_valid_interface(self, validator, valid_config):
        """Test valid interface passes validation."""
        issues = validator.validate(valid_config)

        interface_errors = [
            i for i in issues
            if "Interface" in i.location and i.severity == Severity.ERROR
        ]
        assert len(interface_errors) == 0

    def test_duplicate_ip_addresses(self, validator):
        """Test duplicate IP addresses detected."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            interfaces=[
                Interface(
                    name="Gi0/0",
                    interface_type=InterfaceType.GIGABIT,
                    ip_address="10.0.0.1",
                    subnet_mask="255.255.255.0",
                ),
                Interface(
                    name="Gi0/1",
                    interface_type=InterfaceType.GIGABIT,
                    ip_address="10.0.0.1",
                    subnet_mask="255.255.255.0",
                ),
            ],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.ERROR and "Duplicate IP address" in i.message
            for i in issues
        )

    def test_invalid_ip_address(self, validator):
        """Test invalid IP address detected."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            interfaces=[
                Interface(
                    name="Gi0/0",
                    interface_type=InterfaceType.GIGABIT,
                    ip_address="999.999.999.999",
                    subnet_mask="255.255.255.0",
                ),
            ],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.ERROR and "Invalid IP address" in i.message
            for i in issues
        )

    def test_reserved_vlan_warning(self, validator):
        """Test reserved VLAN usage generates warning."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            interfaces=[
                Interface(
                    name="Gi0/0",
                    interface_type=InterfaceType.GIGABIT,
                    vlan_id=1,  # Reserved VLAN
                ),
            ],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.WARNING and "reserved VLAN" in i.message
            for i in issues
        )

    def test_trunk_all_vlans_warning(self, validator):
        """Test trunk allowing all VLANs generates warning."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            interfaces=[
                Interface(
                    name="Gi0/0",
                    interface_type=InterfaceType.GIGABIT,
                    is_trunk=True,
                    trunk_allowed_vlans=None,  # All VLANs allowed
                ),
            ],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.WARNING
            and i.category == Category.SECURITY
            and "all VLANs" in i.message
            for i in issues
        )

    def test_interface_without_description(self, validator):
        """Test interface with IP but no description generates info."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            interfaces=[
                Interface(
                    name="Gi0/0",
                    interface_type=InterfaceType.GIGABIT,
                    ip_address="10.0.0.1",
                    subnet_mask="255.255.255.0",
                    description="",  # No description
                ),
            ],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.INFO and "no description" in i.message.lower()
            for i in issues
        )


class TestVLANValidation:
    """Tests for VLAN validation."""

    def test_duplicate_vlans(self, validator):
        """Test duplicate VLAN IDs detected."""
        config = DeviceConfig(
            hostname="switch1",
            vendor=Vendor.CISCO_IOS,
            vlans=[
                VLAN(vlan_id=10, name="DATA1"),
                VLAN(vlan_id=10, name="DATA2"),
            ],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.ERROR and "Duplicate VLAN ID" in i.message
            for i in issues
        )

    def test_generic_vlan_name(self, validator):
        """Test generic VLAN name generates info."""
        config = DeviceConfig(
            hostname="switch1",
            vendor=Vendor.CISCO_IOS,
            vlans=[
                VLAN(vlan_id=10, name="VLAN"),
            ],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.INFO and "generic" in i.message.lower()
            for i in issues
        )


class TestACLValidation:
    """Tests for ACL validation."""

    def test_empty_acl_warning(self, validator):
        """Test empty ACL generates warning."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            acls=[ACL(name="EMPTY-ACL", entries=[])],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.WARNING and "Empty ACL" in i.message
            for i in issues
        )

    def test_duplicate_sequence_numbers(self, validator):
        """Test duplicate sequence numbers detected."""
        acl = ACL(name="TEST-ACL")
        acl.entries = [
            ACLEntry(sequence=10, action=ACLAction.PERMIT, protocol=ACLProtocol.IP,
                     source="any", destination="any"),
            ACLEntry(sequence=10, action=ACLAction.DENY, protocol=ACLProtocol.IP,
                     source="any", destination="any"),
        ]

        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            acls=[acl],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.ERROR and "Duplicate sequence" in i.message
            for i in issues
        )


class TestRoutingValidation:
    """Tests for routing validation."""

    def test_ospf_no_router_id_warning(self, validator):
        """Test OSPF without router-id generates warning."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            ospf=OSPFConfig(
                process_id=1,
                router_id=None,
                networks=[OSPFNetwork(network="10.0.0.0", wildcard="0.0.0.255", area=0)],
            ),
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.WARNING and "router-id not explicitly configured" in i.message
            for i in issues
        )

    def test_bgp_no_authentication_warning(self, validator):
        """Test BGP neighbor without auth generates warning."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            bgp=BGPConfig(
                local_as=65000,
                neighbors=[
                    BGPNeighbor(
                        ip_address="10.0.0.2",
                        remote_as=65001,
                        password=None,  # No auth
                    ),
                ],
            ),
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.WARNING
            and i.category == Category.SECURITY
            and "no MD5 authentication" in i.message
            for i in issues
        )


class TestSecurityValidation:
    """Tests for security validation."""

    def test_no_enable_secret_warning(self, validator):
        """Test missing enable secret generates warning."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            enable_secret=None,
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.WARNING
            and i.category == Category.SECURITY
            and "enable secret" in i.message.lower()
            for i in issues
        )

    def test_weak_password_detected(self, validator):
        """Test weak password detected."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            enable_secret="cisco",  # Weak password
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.ERROR
            and i.category == Category.SECURITY
            and "Weak enable secret" in i.message
            for i in issues
        )


class TestBestPracticesValidation:
    """Tests for best practices validation."""

    def test_no_ntp_info(self, validator):
        """Test missing NTP generates info."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            ntp_servers=[],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.INFO and "NTP" in i.message
            for i in issues
        )

    def test_no_dns_info(self, validator):
        """Test missing DNS generates info."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            dns_servers=[],
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.INFO and "DNS" in i.message
            for i in issues
        )

    def test_no_banner_info(self, validator):
        """Test missing banner generates info."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            banner_motd="",
        )

        issues = validator.validate(config)

        assert any(
            i.severity == Severity.INFO and "banner" in i.message.lower()
            for i in issues
        )


class TestValidatorSummary:
    """Tests for validator summary functionality."""

    def test_get_summary(self, validator):
        """Test summary generation."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            enable_secret="cisco",  # Weak - ERROR
            ntp_servers=[],  # Missing - INFO
        )

        validator.validate(config)
        summary = validator.get_summary()

        assert "total" in summary
        assert "by_severity" in summary
        assert "by_category" in summary
        assert summary["total"] > 0
