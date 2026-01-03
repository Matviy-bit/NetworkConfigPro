"""Tests for data models."""

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


class TestInterface:
    """Tests for Interface model."""

    def test_basic_interface(self):
        """Test creating a basic interface."""
        iface = Interface(
            name="GigabitEthernet0/0",
            interface_type=InterfaceType.GIGABIT,
            description="Uplink to core",
            ip_address="10.0.0.1",
            subnet_mask="255.255.255.0",
        )

        assert iface.name == "GigabitEthernet0/0"
        assert iface.interface_type == InterfaceType.GIGABIT
        assert iface.ip_address == "10.0.0.1"
        assert iface.enabled is True
        assert iface.mtu == 1500

    def test_interface_with_vlan(self):
        """Test interface with VLAN assignment."""
        iface = Interface(
            name="GigabitEthernet0/1",
            interface_type=InterfaceType.GIGABIT,
            vlan_id=100,
        )

        assert iface.vlan_id == 100
        assert iface.is_trunk is False

    def test_trunk_interface(self):
        """Test trunk interface configuration."""
        iface = Interface(
            name="GigabitEthernet0/2",
            interface_type=InterfaceType.GIGABIT,
            is_trunk=True,
            trunk_allowed_vlans="10,20,30",
            native_vlan=1,
        )

        assert iface.is_trunk is True
        assert iface.trunk_allowed_vlans == "10,20,30"
        assert iface.native_vlan == 1

    def test_invalid_vlan_id(self):
        """Test that invalid VLAN ID raises error."""
        with pytest.raises(ValueError, match="VLAN ID must be between 1 and 4094"):
            Interface(
                name="Gi0/0",
                interface_type=InterfaceType.GIGABIT,
                vlan_id=5000,
            )

    def test_invalid_mtu_low(self):
        """Test that MTU too low raises error."""
        with pytest.raises(ValueError, match="MTU must be between 64 and 9216"):
            Interface(
                name="Gi0/0",
                interface_type=InterfaceType.GIGABIT,
                mtu=32,
            )

    def test_invalid_mtu_high(self):
        """Test that MTU too high raises error."""
        with pytest.raises(ValueError, match="MTU must be between 64 and 9216"):
            Interface(
                name="Gi0/0",
                interface_type=InterfaceType.GIGABIT,
                mtu=10000,
            )


class TestVLAN:
    """Tests for VLAN model."""

    def test_basic_vlan(self):
        """Test creating a basic VLAN."""
        vlan = VLAN(vlan_id=100, name="DATA")

        assert vlan.vlan_id == 100
        assert vlan.name == "DATA"
        assert vlan.state == "active"

    def test_vlan_with_description(self):
        """Test VLAN with description."""
        vlan = VLAN(
            vlan_id=200,
            name="VOICE",
            description="Voice traffic VLAN",
        )

        assert vlan.description == "Voice traffic VLAN"

    def test_invalid_vlan_id_low(self):
        """Test that VLAN ID below 1 raises error."""
        with pytest.raises(ValueError, match="VLAN ID must be between 1 and 4094"):
            VLAN(vlan_id=0, name="INVALID")

    def test_invalid_vlan_id_high(self):
        """Test that VLAN ID above 4094 raises error."""
        with pytest.raises(ValueError, match="VLAN ID must be between 1 and 4094"):
            VLAN(vlan_id=4095, name="INVALID")

    def test_empty_name_raises_error(self):
        """Test that empty VLAN name raises error."""
        with pytest.raises(ValueError, match="VLAN name cannot be empty"):
            VLAN(vlan_id=100, name="")


class TestACL:
    """Tests for ACL model."""

    def test_basic_acl(self):
        """Test creating a basic ACL."""
        acl = ACL(name="DENY-TELNET", is_extended=True)

        assert acl.name == "DENY-TELNET"
        assert acl.is_extended is True
        assert len(acl.entries) == 0

    def test_add_entry(self):
        """Test adding entries to ACL."""
        acl = ACL(name="TEST-ACL")

        entry1 = ACLEntry(
            sequence=10,
            action=ACLAction.DENY,
            protocol=ACLProtocol.TCP,
            source="any",
            destination="any",
            destination_port="23",
        )

        entry2 = ACLEntry(
            sequence=20,
            action=ACLAction.PERMIT,
            protocol=ACLProtocol.IP,
            source="any",
            destination="any",
        )

        acl.add_entry(entry2)
        acl.add_entry(entry1)

        # Entries should be sorted by sequence
        assert len(acl.entries) == 2
        assert acl.entries[0].sequence == 10
        assert acl.entries[1].sequence == 20


class TestStaticRoute:
    """Tests for StaticRoute model."""

    def test_basic_route(self):
        """Test creating a basic static route."""
        route = StaticRoute(
            destination="0.0.0.0",
            mask="0.0.0.0",
            next_hop="10.0.0.1",
        )

        assert route.destination == "0.0.0.0"
        assert route.admin_distance == 1

    def test_route_with_admin_distance(self):
        """Test route with custom admin distance."""
        route = StaticRoute(
            destination="192.168.0.0",
            mask="255.255.255.0",
            next_hop="10.0.0.1",
            admin_distance=200,
            name="backup-route",
        )

        assert route.admin_distance == 200
        assert route.name == "backup-route"

    def test_invalid_admin_distance(self):
        """Test that invalid admin distance raises error."""
        with pytest.raises(ValueError, match="Admin distance must be 1-255"):
            StaticRoute(
                destination="0.0.0.0",
                mask="0.0.0.0",
                next_hop="10.0.0.1",
                admin_distance=256,
            )


class TestOSPFConfig:
    """Tests for OSPFConfig model."""

    def test_basic_ospf(self):
        """Test creating basic OSPF config."""
        ospf = OSPFConfig(process_id=1)

        assert ospf.process_id == 1
        assert ospf.router_id is None
        assert ospf.reference_bandwidth == 100

    def test_ospf_with_networks(self):
        """Test OSPF with network statements."""
        ospf = OSPFConfig(
            process_id=100,
            router_id="1.1.1.1",
            networks=[
                OSPFNetwork(network="10.0.0.0", wildcard="0.0.0.255", area=0),
                OSPFNetwork(network="192.168.1.0", wildcard="0.0.0.255", area=1),
            ],
        )

        assert len(ospf.networks) == 2
        assert ospf.networks[0].area == 0

    def test_invalid_process_id(self):
        """Test that invalid process ID raises error."""
        # 0 is now allowed for Junos compatibility, but negative is not
        with pytest.raises(ValueError, match="OSPF process ID must be 0-65535"):
            OSPFConfig(process_id=-1)


class TestBGPConfig:
    """Tests for BGPConfig model."""

    def test_basic_bgp(self):
        """Test creating basic BGP config."""
        bgp = BGPConfig(local_as=65000)

        assert bgp.local_as == 65000
        assert bgp.log_neighbor_changes is True

    def test_bgp_with_neighbors(self):
        """Test BGP with neighbors."""
        bgp = BGPConfig(
            local_as=65000,
            router_id="1.1.1.1",
            neighbors=[
                BGPNeighbor(
                    ip_address="10.0.0.2",
                    remote_as=65001,
                    description="Peer1",
                ),
            ],
        )

        assert len(bgp.neighbors) == 1
        assert bgp.neighbors[0].remote_as == 65001

    def test_invalid_as_number(self):
        """Test that invalid AS number raises error."""
        with pytest.raises(ValueError, match="BGP AS must be 1-4294967295"):
            BGPConfig(local_as=0)


class TestDeviceConfig:
    """Tests for DeviceConfig model."""

    def test_complete_config(self):
        """Test creating a complete device config."""
        config = DeviceConfig(
            hostname="router1",
            vendor=Vendor.CISCO_IOS,
            domain_name="example.com",
            dns_servers=["8.8.8.8", "8.8.4.4"],
            ntp_servers=["pool.ntp.org"],
            interfaces=[
                Interface(
                    name="Gi0/0",
                    interface_type=InterfaceType.GIGABIT,
                    ip_address="10.0.0.1",
                    subnet_mask="255.255.255.0",
                ),
            ],
            vlans=[
                VLAN(vlan_id=10, name="DATA"),
            ],
        )

        assert config.hostname == "router1"
        assert config.vendor == Vendor.CISCO_IOS
        assert len(config.interfaces) == 1
        assert len(config.vlans) == 1
