"""Configuration validators and best-practice checkers."""

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..models import (
    ACL,
    ACLAction,
    DeviceConfig,
    Interface,
    OSPFConfig,
    BGPConfig,
    StaticRoute,
    VLAN,
)


class Severity(Enum):
    """Validation issue severity levels."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Category(Enum):
    """Validation issue categories."""
    SECURITY = "security"
    SYNTAX = "syntax"
    BEST_PRACTICE = "best_practice"
    PERFORMANCE = "performance"
    REDUNDANCY = "redundancy"


@dataclass
class ValidationIssue:
    """Represents a validation issue found in configuration."""
    severity: Severity
    category: Category
    message: str
    location: str
    recommendation: str = ""


class ConfigValidator:
    """Validates network configurations and checks for best practices."""

    # Common weak passwords to check against
    WEAK_PASSWORDS = {
        "cisco", "admin", "password", "123456", "cisco123",
        "default", "test", "changeme", "secret", "enable",
    }

    # Reserved VLAN IDs
    RESERVED_VLANS = {1, 1002, 1003, 1004, 1005, 4094}

    def __init__(self):
        """Initialize the validator."""
        self.issues: list[ValidationIssue] = []

    def validate(self, config: DeviceConfig) -> list[ValidationIssue]:
        """Run all validations on a device configuration.

        Args:
            config: DeviceConfig to validate

        Returns:
            List of validation issues found
        """
        self.issues = []

        # Run all validation checks
        self._validate_hostname(config)
        self._validate_interfaces(config)
        self._validate_vlans(config)
        self._validate_acls(config)
        self._validate_static_routes(config)
        self._validate_ospf(config)
        self._validate_bgp(config)
        self._validate_security(config)
        self._check_best_practices(config)

        return self.issues

    def _add_issue(
        self,
        severity: Severity,
        category: Category,
        message: str,
        location: str,
        recommendation: str = "",
    ) -> None:
        """Add a validation issue to the list."""
        self.issues.append(
            ValidationIssue(
                severity=severity,
                category=category,
                message=message,
                location=location,
                recommendation=recommendation,
            )
        )

    def _validate_hostname(self, config: DeviceConfig) -> None:
        """Validate hostname configuration."""
        if not config.hostname:
            self._add_issue(
                Severity.ERROR,
                Category.SYNTAX,
                "Hostname is not configured",
                "Global",
                "Configure a hostname for the device",
            )
            return

        # Check hostname format
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9\-_]*$", config.hostname):
            self._add_issue(
                Severity.ERROR,
                Category.SYNTAX,
                f"Invalid hostname format: {config.hostname}",
                "Global",
                "Hostname must start with a letter and contain only letters, numbers, hyphens, and underscores",
            )

        if len(config.hostname) > 63:
            self._add_issue(
                Severity.ERROR,
                Category.SYNTAX,
                f"Hostname too long: {len(config.hostname)} characters",
                "Global",
                "Hostname must be 63 characters or less",
            )

    def _validate_interfaces(self, config: DeviceConfig) -> None:
        """Validate interface configurations."""
        used_ips = {}
        used_vlans = {}

        for iface in config.interfaces:
            location = f"Interface {iface.name}"

            # Check for duplicate IP addresses
            if iface.ip_address:
                if not self._is_valid_ip(iface.ip_address):
                    self._add_issue(
                        Severity.ERROR,
                        Category.SYNTAX,
                        f"Invalid IP address: {iface.ip_address}",
                        location,
                        "Use a valid IPv4 address format",
                    )
                elif iface.ip_address in used_ips:
                    self._add_issue(
                        Severity.ERROR,
                        Category.REDUNDANCY,
                        f"Duplicate IP address: {iface.ip_address} (also on {used_ips[iface.ip_address]})",
                        location,
                        "Each interface must have a unique IP address",
                    )
                else:
                    used_ips[iface.ip_address] = iface.name

            # Validate subnet mask
            if iface.subnet_mask and not self._is_valid_subnet_mask(iface.subnet_mask):
                self._add_issue(
                    Severity.ERROR,
                    Category.SYNTAX,
                    f"Invalid subnet mask: {iface.subnet_mask}",
                    location,
                    "Use a valid subnet mask (e.g., 255.255.255.0)",
                )

            # Check VLAN configuration
            if iface.vlan_id:
                if iface.vlan_id in self.RESERVED_VLANS:
                    self._add_issue(
                        Severity.WARNING,
                        Category.BEST_PRACTICE,
                        f"Using reserved VLAN {iface.vlan_id}",
                        location,
                        "Avoid using reserved VLANs (1, 1002-1005, 4094)",
                    )

            # Check trunk configuration
            if iface.is_trunk:
                if not iface.trunk_allowed_vlans:
                    self._add_issue(
                        Severity.WARNING,
                        Category.SECURITY,
                        "Trunk interface allows all VLANs",
                        location,
                        "Explicitly configure allowed VLANs on trunk interfaces",
                    )

            # MTU validation
            if iface.mtu < 576:
                self._add_issue(
                    Severity.ERROR,
                    Category.SYNTAX,
                    f"MTU too small: {iface.mtu}",
                    location,
                    "MTU should be at least 576 bytes for IPv4",
                )

            # Check for description on important interfaces
            if iface.ip_address and not iface.description:
                self._add_issue(
                    Severity.INFO,
                    Category.BEST_PRACTICE,
                    "Interface with IP has no description",
                    location,
                    "Add descriptions to routed interfaces for documentation",
                )

    def _validate_vlans(self, config: DeviceConfig) -> None:
        """Validate VLAN configurations."""
        seen_vlans = {}

        for vlan in config.vlans:
            location = f"VLAN {vlan.vlan_id}"

            # Check for duplicates
            if vlan.vlan_id in seen_vlans:
                self._add_issue(
                    Severity.ERROR,
                    Category.REDUNDANCY,
                    f"Duplicate VLAN ID: {vlan.vlan_id}",
                    location,
                    "Remove duplicate VLAN definition",
                )
            else:
                seen_vlans[vlan.vlan_id] = vlan.name

            # Check reserved VLANs
            if vlan.vlan_id in self.RESERVED_VLANS:
                self._add_issue(
                    Severity.WARNING,
                    Category.BEST_PRACTICE,
                    f"Configuring reserved VLAN {vlan.vlan_id}",
                    location,
                    "Reserved VLANs should generally not be modified",
                )

            # Check VLAN name
            if not vlan.name or vlan.name.lower() in ("vlan", "default"):
                self._add_issue(
                    Severity.INFO,
                    Category.BEST_PRACTICE,
                    "VLAN has generic or no name",
                    location,
                    "Use descriptive VLAN names",
                )

    def _validate_acls(self, config: DeviceConfig) -> None:
        """Validate ACL configurations."""
        for acl in config.acls:
            location = f"ACL {acl.name}"
            has_deny_any = False
            has_permit = False
            sequences = set()

            for entry in acl.entries:
                entry_location = f"{location} seq {entry.sequence}"

                # Check for duplicate sequences
                if entry.sequence in sequences:
                    self._add_issue(
                        Severity.ERROR,
                        Category.REDUNDANCY,
                        f"Duplicate sequence number: {entry.sequence}",
                        entry_location,
                        "Use unique sequence numbers",
                    )
                sequences.add(entry.sequence)

                # Track permit/deny
                if entry.action == ACLAction.PERMIT:
                    has_permit = True
                if entry.action == ACLAction.DENY and entry.source == "any" and entry.destination == "any":
                    has_deny_any = True

                # Validate IP addresses in ACL
                if entry.source != "any" and not self._is_valid_ip_or_network(entry.source):
                    self._add_issue(
                        Severity.ERROR,
                        Category.SYNTAX,
                        f"Invalid source in ACL: {entry.source}",
                        entry_location,
                        "Use a valid IP address or 'any'",
                    )

            # Check for implicit deny warning
            if has_permit and not has_deny_any:
                self._add_issue(
                    Severity.INFO,
                    Category.SECURITY,
                    "ACL has implicit deny at end",
                    location,
                    "Consider adding explicit deny any any with logging for visibility",
                )

            # Empty ACL warning
            if not acl.entries:
                self._add_issue(
                    Severity.WARNING,
                    Category.SYNTAX,
                    "Empty ACL defined",
                    location,
                    "Add entries or remove unused ACL",
                )

    def _validate_static_routes(self, config: DeviceConfig) -> None:
        """Validate static route configurations."""
        seen_routes = set()

        for route in config.static_routes:
            location = f"Static route to {route.destination}/{route.mask}"
            route_key = (route.destination, route.mask, route.next_hop)

            # Check for duplicates
            if route_key in seen_routes:
                self._add_issue(
                    Severity.WARNING,
                    Category.REDUNDANCY,
                    f"Duplicate static route: {route.destination}",
                    location,
                    "Remove duplicate route definition",
                )
            seen_routes.add(route_key)

            # Validate destination
            if not self._is_valid_ip(route.destination):
                self._add_issue(
                    Severity.ERROR,
                    Category.SYNTAX,
                    f"Invalid destination: {route.destination}",
                    location,
                    "Use a valid network address",
                )

            # Validate next-hop
            if not self._is_valid_ip(route.next_hop):
                self._add_issue(
                    Severity.ERROR,
                    Category.SYNTAX,
                    f"Invalid next-hop: {route.next_hop}",
                    location,
                    "Use a valid next-hop IP address",
                )

            # Check for default route
            if route.destination == "0.0.0.0" and route.mask == "0.0.0.0":
                self._add_issue(
                    Severity.INFO,
                    Category.BEST_PRACTICE,
                    "Default route configured via static routing",
                    location,
                    "Consider using a dynamic routing protocol for redundancy",
                )

    def _validate_ospf(self, config: DeviceConfig) -> None:
        """Validate OSPF configuration."""
        if not config.ospf:
            return

        ospf = config.ospf
        location = f"OSPF process {ospf.process_id}"

        # Check router ID
        if not ospf.router_id:
            self._add_issue(
                Severity.WARNING,
                Category.BEST_PRACTICE,
                "OSPF router-id not explicitly configured",
                location,
                "Explicitly configure router-id for stability",
            )
        elif not self._is_valid_ip(ospf.router_id):
            self._add_issue(
                Severity.ERROR,
                Category.SYNTAX,
                f"Invalid OSPF router-id: {ospf.router_id}",
                location,
                "Use a valid IP address for router-id",
            )

        # Check reference bandwidth
        if ospf.reference_bandwidth < 1000:
            self._add_issue(
                Severity.INFO,
                Category.PERFORMANCE,
                f"Low OSPF reference bandwidth: {ospf.reference_bandwidth}",
                location,
                "Consider increasing reference-bandwidth for high-speed links",
            )

        # Check for networks
        if not ospf.networks:
            self._add_issue(
                Severity.WARNING,
                Category.SYNTAX,
                "OSPF configured but no networks advertised",
                location,
                "Add network statements to advertise routes",
            )

    def _validate_bgp(self, config: DeviceConfig) -> None:
        """Validate BGP configuration."""
        if not config.bgp:
            return

        bgp = config.bgp
        location = f"BGP AS {bgp.local_as}"

        # Check router ID
        if not bgp.router_id:
            self._add_issue(
                Severity.WARNING,
                Category.BEST_PRACTICE,
                "BGP router-id not explicitly configured",
                location,
                "Explicitly configure router-id for stability",
            )

        # Check neighbors
        if not bgp.neighbors:
            self._add_issue(
                Severity.WARNING,
                Category.SYNTAX,
                "BGP configured but no neighbors defined",
                location,
                "Add BGP neighbor configurations",
            )

        for neighbor in bgp.neighbors:
            neighbor_location = f"{location} neighbor {neighbor.ip_address}"

            # Validate neighbor IP
            if not self._is_valid_ip(neighbor.ip_address):
                self._add_issue(
                    Severity.ERROR,
                    Category.SYNTAX,
                    f"Invalid neighbor IP: {neighbor.ip_address}",
                    neighbor_location,
                    "Use a valid IP address",
                )

            # Check for authentication
            if not neighbor.password:
                self._add_issue(
                    Severity.WARNING,
                    Category.SECURITY,
                    "BGP neighbor has no MD5 authentication",
                    neighbor_location,
                    "Configure MD5 authentication for BGP security",
                )

            # Check for description
            if not neighbor.description:
                self._add_issue(
                    Severity.INFO,
                    Category.BEST_PRACTICE,
                    "BGP neighbor has no description",
                    neighbor_location,
                    "Add description for documentation",
                )

    def _validate_security(self, config: DeviceConfig) -> None:
        """Validate security-related configurations."""
        # Check enable secret
        if not config.enable_secret:
            self._add_issue(
                Severity.WARNING,
                Category.SECURITY,
                "No enable secret configured",
                "Global",
                "Configure an enable secret for privileged access",
            )
        elif config.enable_secret.lower() in self.WEAK_PASSWORDS:
            self._add_issue(
                Severity.ERROR,
                Category.SECURITY,
                "Weak enable secret detected",
                "Global",
                "Use a strong, unique password",
            )

        # Check for any BGP passwords
        if config.bgp:
            for neighbor in config.bgp.neighbors:
                if neighbor.password and neighbor.password.lower() in self.WEAK_PASSWORDS:
                    self._add_issue(
                        Severity.ERROR,
                        Category.SECURITY,
                        f"Weak BGP password for neighbor {neighbor.ip_address}",
                        f"BGP neighbor {neighbor.ip_address}",
                        "Use a strong, unique password",
                    )

    def _check_best_practices(self, config: DeviceConfig) -> None:
        """Check for general best practices."""
        # Check for NTP
        if not config.ntp_servers:
            self._add_issue(
                Severity.INFO,
                Category.BEST_PRACTICE,
                "No NTP servers configured",
                "Global",
                "Configure NTP for accurate time synchronization",
            )

        # Check for DNS
        if not config.dns_servers:
            self._add_issue(
                Severity.INFO,
                Category.BEST_PRACTICE,
                "No DNS servers configured",
                "Global",
                "Configure DNS servers for name resolution",
            )

        # Check for domain name
        if not config.domain_name:
            self._add_issue(
                Severity.INFO,
                Category.BEST_PRACTICE,
                "No domain name configured",
                "Global",
                "Configure domain name for SSH key generation",
            )

        # Check for banner
        if not config.banner_motd:
            self._add_issue(
                Severity.INFO,
                Category.SECURITY,
                "No login banner configured",
                "Global",
                "Configure a login banner for legal notice",
            )

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def _is_valid_ip_or_network(value: str) -> bool:
        """Check if string is a valid IP address or network."""
        try:
            ipaddress.IPv4Address(value)
            return True
        except (ipaddress.AddressValueError, ValueError):
            pass
        try:
            ipaddress.IPv4Network(value, strict=False)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def _is_valid_subnet_mask(mask: str) -> bool:
        """Check if string is a valid subnet mask."""
        try:
            octets = [int(o) for o in mask.split(".")]
            if len(octets) != 4:
                return False
            # Convert to binary and check it's a valid mask
            binary = "".join(format(o, "08b") for o in octets)
            # Valid mask is all 1s followed by all 0s
            if "01" in binary:
                return False
            return all(0 <= o <= 255 for o in octets)
        except (ValueError, AttributeError):
            return False

    def get_summary(self) -> dict:
        """Get a summary of validation results.

        Returns:
            Dictionary with counts by severity and category
        """
        summary = {
            "total": len(self.issues),
            "by_severity": {},
            "by_category": {},
        }

        for severity in Severity:
            count = len([i for i in self.issues if i.severity == severity])
            if count > 0:
                summary["by_severity"][severity.value] = count

        for category in Category:
            count = len([i for i in self.issues if i.category == category])
            if count > 0:
                summary["by_category"][category.value] = count

        return summary
