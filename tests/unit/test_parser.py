"""Tests for configuration parser."""

import pytest

from src.core.models import Vendor
from src.core.parsers.config_parser import CiscoIOSParser, ConfigParserFactory


@pytest.fixture
def ios_parser():
    """Create a Cisco IOS parser instance."""
    return CiscoIOSParser()


@pytest.fixture
def sample_ios_config():
    """Sample Cisco IOS configuration."""
    return """
!
version 15.2
!
hostname test-router
!
enable secret 5 $1$abc$xyz
!
ip domain-name example.com
!
ip name-server 8.8.8.8
ip name-server 8.8.4.4
!
ntp server pool.ntp.org
!
banner motd ^
Authorized access only!
^
!
vlan 10
 name DATA
!
vlan 20
 name VOICE
!
interface GigabitEthernet0/0
 description WAN Uplink
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 description LAN Access
 switchport mode access
 switchport access vlan 10
 shutdown
!
interface GigabitEthernet0/2
 description Trunk to Switch
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 switchport trunk native vlan 1
 no shutdown
!
ip access-list extended BLOCK-TELNET
 10 deny tcp any any eq 23 log
 20 permit ip any any
!
ip route 0.0.0.0 0.0.0.0 10.0.0.254
ip route 192.168.100.0 255.255.255.0 10.0.0.2 200 name backup
!
router ospf 1
 router-id 1.1.1.1
 auto-cost reference-bandwidth 10000
 network 10.0.0.0 0.0.0.255 area 0
 network 192.168.1.0 0.0.0.255 area 1
 passive-interface GigabitEthernet0/1
 default-information originate
!
router bgp 65000
 bgp router-id 1.1.1.1
 bgp log-neighbor-changes
 network 10.0.0.0/24
 neighbor 10.0.0.2 remote-as 65001
 neighbor 10.0.0.2 description ISP Peer
 neighbor 10.0.0.2 password SecretBGP
 neighbor 10.0.0.2 update-source Loopback0
 neighbor 10.0.0.2 ebgp-multihop 2
!
end
"""


class TestCiscoIOSParser:
    """Tests for Cisco IOS parser."""

    def test_detect_vendor_positive(self, ios_parser, sample_ios_config):
        """Test that IOS config is detected correctly."""
        assert ios_parser.detect_vendor(sample_ios_config) is True

    def test_detect_vendor_negative(self, ios_parser):
        """Test that non-IOS config is not detected."""
        junos_config = """
system {
    host-name juniper-router;
}
"""
        assert ios_parser.detect_vendor(junos_config) is False

    def test_parse_hostname(self, ios_parser, sample_ios_config):
        """Test hostname parsing."""
        result = ios_parser.parse(sample_ios_config)

        assert result.config is not None
        assert result.config.hostname == "test-router"

    def test_parse_domain_name(self, ios_parser, sample_ios_config):
        """Test domain name parsing."""
        result = ios_parser.parse(sample_ios_config)

        assert result.config.domain_name == "example.com"

    def test_parse_dns_servers(self, ios_parser, sample_ios_config):
        """Test DNS server parsing."""
        result = ios_parser.parse(sample_ios_config)

        assert "8.8.8.8" in result.config.dns_servers
        assert "8.8.4.4" in result.config.dns_servers

    def test_parse_ntp_servers(self, ios_parser, sample_ios_config):
        """Test NTP server parsing."""
        result = ios_parser.parse(sample_ios_config)

        assert "pool.ntp.org" in result.config.ntp_servers

    def test_parse_banner(self, ios_parser, sample_ios_config):
        """Test banner parsing."""
        result = ios_parser.parse(sample_ios_config)

        assert "Authorized access only!" in result.config.banner_motd

    def test_parse_vlans(self, ios_parser, sample_ios_config):
        """Test VLAN parsing."""
        result = ios_parser.parse(sample_ios_config)

        assert len(result.config.vlans) == 2
        vlan_ids = [v.vlan_id for v in result.config.vlans]
        assert 10 in vlan_ids
        assert 20 in vlan_ids

        # Check names
        data_vlan = next(v for v in result.config.vlans if v.vlan_id == 10)
        assert data_vlan.name == "DATA"

    def test_parse_interfaces(self, ios_parser, sample_ios_config):
        """Test interface parsing."""
        result = ios_parser.parse(sample_ios_config)

        assert len(result.config.interfaces) == 3

        # Check routed interface
        gi0_0 = next(i for i in result.config.interfaces if "0/0" in i.name)
        assert gi0_0.description == "WAN Uplink"
        assert gi0_0.ip_address == "10.0.0.1"
        assert gi0_0.subnet_mask == "255.255.255.0"
        assert gi0_0.enabled is True

        # Check access interface
        gi0_1 = next(i for i in result.config.interfaces if "0/1" in i.name)
        assert gi0_1.vlan_id == 10
        assert gi0_1.enabled is False

        # Check trunk interface
        gi0_2 = next(i for i in result.config.interfaces if "0/2" in i.name)
        assert gi0_2.is_trunk is True
        assert gi0_2.trunk_allowed_vlans == "10,20,30"
        assert gi0_2.native_vlan == 1

    def test_parse_acls(self, ios_parser, sample_ios_config):
        """Test ACL parsing."""
        result = ios_parser.parse(sample_ios_config)

        assert len(result.config.acls) == 1
        acl = result.config.acls[0]
        assert acl.name == "BLOCK-TELNET"
        assert acl.is_extended is True
        assert len(acl.entries) == 2

    def test_parse_static_routes(self, ios_parser, sample_ios_config):
        """Test static route parsing."""
        result = ios_parser.parse(sample_ios_config)

        assert len(result.config.static_routes) == 2

        # Default route
        default = next(r for r in result.config.static_routes
                       if r.destination == "0.0.0.0")
        assert default.next_hop == "10.0.0.254"
        assert default.admin_distance == 1

        # Named route with admin distance
        backup = next(r for r in result.config.static_routes
                      if r.destination == "192.168.100.0")
        assert backup.admin_distance == 200
        assert backup.name == "backup"

    def test_parse_ospf(self, ios_parser, sample_ios_config):
        """Test OSPF parsing."""
        result = ios_parser.parse(sample_ios_config)

        ospf = result.config.ospf
        assert ospf is not None
        assert ospf.process_id == 1
        assert ospf.router_id == "1.1.1.1"
        assert ospf.reference_bandwidth == 10000
        assert len(ospf.networks) == 2
        assert ospf.default_information_originate is True
        assert "GigabitEthernet0/1" in ospf.passive_interfaces

    def test_parse_bgp(self, ios_parser, sample_ios_config):
        """Test BGP parsing."""
        result = ios_parser.parse(sample_ios_config)

        bgp = result.config.bgp
        assert bgp is not None
        assert bgp.local_as == 65000
        assert bgp.router_id == "1.1.1.1"
        assert bgp.log_neighbor_changes is True
        assert len(bgp.neighbors) == 1

        neighbor = bgp.neighbors[0]
        assert neighbor.ip_address == "10.0.0.2"
        assert neighbor.remote_as == 65001
        assert neighbor.description == "ISP Peer"
        assert neighbor.password == "SecretBGP"
        assert neighbor.update_source == "Loopback0"
        assert neighbor.ebgp_multihop == 2

    def test_parse_result_no_errors(self, ios_parser, sample_ios_config):
        """Test that valid config has no parse errors."""
        result = ios_parser.parse(sample_ios_config)

        assert len(result.errors) == 0
        assert result.vendor == Vendor.CISCO_IOS


class TestConfigParserFactory:
    """Tests for ConfigParserFactory."""

    def test_detect_and_parse_ios(self, sample_ios_config):
        """Test auto-detection and parsing of IOS config."""
        result = ConfigParserFactory.detect_and_parse(sample_ios_config)

        assert result.config is not None
        assert result.vendor == Vendor.CISCO_IOS
        assert result.config.hostname == "test-router"

    def test_parse_with_known_vendor(self, sample_ios_config):
        """Test parsing with explicitly specified vendor."""
        result = ConfigParserFactory.parse_with_vendor(
            sample_ios_config,
            Vendor.CISCO_IOS
        )

        assert result.config is not None
        assert result.config.hostname == "test-router"

    def test_unknown_format_error(self):
        """Test that unknown format returns error."""
        unknown_config = """
some random text
that is not a network config
"""
        result = ConfigParserFactory.detect_and_parse(unknown_config)

        assert result.config is None
        assert len(result.errors) > 0

    def test_missing_hostname_warning(self, ios_parser):
        """Test that missing hostname generates warning."""
        minimal_config = """
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
!
"""
        result = ios_parser.parse(minimal_config)

        assert any("hostname" in w.lower() for w in result.warnings)


class TestInterfaceTypeParsing:
    """Tests for interface type detection."""

    def test_detect_gigabit(self, ios_parser):
        """Test GigabitEthernet detection."""
        config = """
hostname router
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
"""
        result = ios_parser.parse(config)
        iface = result.config.interfaces[0]

        from src.core.models import InterfaceType
        assert iface.interface_type == InterfaceType.GIGABIT

    def test_detect_loopback(self, ios_parser):
        """Test Loopback detection."""
        config = """
hostname router
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
"""
        result = ios_parser.parse(config)
        iface = result.config.interfaces[0]

        from src.core.models import InterfaceType
        assert iface.interface_type == InterfaceType.LOOPBACK

    def test_detect_vlan_interface(self, ios_parser):
        """Test VLAN interface detection."""
        config = """
hostname router
interface Vlan100
 ip address 192.168.100.1 255.255.255.0
"""
        result = ios_parser.parse(config)
        iface = result.config.interfaces[0]

        from src.core.models import InterfaceType
        assert iface.interface_type == InterfaceType.VLAN
