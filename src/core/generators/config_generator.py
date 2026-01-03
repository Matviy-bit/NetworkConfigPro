"""Configuration generator using Jinja2 templates."""

import os
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import DeviceConfig, Vendor


class ConfigGenerator:
    """Generates network device configurations from templates."""

    TEMPLATE_MAP = {
        Vendor.CISCO_IOS: "cisco_ios.j2",
        Vendor.CISCO_NXOS: "cisco_nxos.j2",
        Vendor.ARISTA_EOS: "arista_eos.j2",
        Vendor.JUNIPER_JUNOS: "juniper_junos.j2",
    }

    def __init__(self):
        """Initialize the config generator with Jinja2 environment."""
        template_dir = Path(__file__).parent.parent / "templates" / "vendors"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(default=False),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._register_filters()

    def _register_filters(self) -> None:
        """Register custom Jinja2 filters."""
        self.env.filters["cidr_prefix"] = self._subnet_to_cidr
        self.env.filters["junos_interface_name"] = self._junos_interface_name

    @staticmethod
    def _subnet_to_cidr(subnet_mask: str) -> int:
        """Convert subnet mask to CIDR prefix length.

        Args:
            subnet_mask: Subnet mask in dotted decimal (e.g., "255.255.255.0")

        Returns:
            CIDR prefix length (e.g., 24)
        """
        if not subnet_mask:
            return 32

        # Handle if already a number
        if isinstance(subnet_mask, int):
            return subnet_mask

        try:
            # Try to parse as dotted decimal
            octets = subnet_mask.split(".")
            if len(octets) == 4:
                binary = "".join(format(int(octet), "08b") for octet in octets)
                return binary.count("1")
        except (ValueError, AttributeError):
            pass

        # If it's already a CIDR number as string
        try:
            return int(subnet_mask)
        except ValueError:
            return 32

    @staticmethod
    def _junos_interface_name(name: str) -> str:
        """Convert interface name to Junos format.

        Args:
            name: Interface name (e.g., "GigabitEthernet0/0")

        Returns:
            Junos-style interface name (e.g., "ge-0/0/0")
        """
        name_lower = name.lower()

        # Common conversions - ordered by specificity (longest patterns first)
        conversions = [
            ("hundredgigabitethernet", "et-"),
            ("fortygigabitethernet", "et-"),
            ("tengigabitethernet", "xe-"),
            ("gigabitethernet", "ge-"),
            ("fastethernet", "fe-"),
            ("ethernet", "et-"),
            ("loopback", "lo"),
            ("port-channel", "ae"),
            ("vlan", "vlan."),
        ]

        for old, new in conversions:
            if old in name_lower:
                # Extract the interface numbers
                remainder = name_lower.replace(old, "").strip()
                # Convert Cisco-style 0/0/0 to Junos-style 0/0/0
                if "/" in remainder:
                    parts = remainder.split("/")
                    if new in ("ge-", "xe-", "fe-", "et-"):
                        return f"{new}{'/'.join(parts)}"
                return f"{new}{remainder}"

        return name

    def generate(self, config: DeviceConfig) -> str:
        """Generate configuration from a DeviceConfig object.

        Args:
            config: DeviceConfig object with all configuration data

        Returns:
            Generated configuration as a string
        """
        template_name = self.TEMPLATE_MAP.get(config.vendor)
        if not template_name:
            raise ValueError(f"Unsupported vendor: {config.vendor}")

        template = self.env.get_template(template_name)

        # Convert dataclass to dict for template rendering
        config_dict = self._config_to_dict(config)

        return template.render(**config_dict)

    def _config_to_dict(self, config: DeviceConfig) -> dict[str, Any]:
        """Convert DeviceConfig to a dictionary for template rendering.

        Args:
            config: DeviceConfig object

        Returns:
            Dictionary representation suitable for Jinja2
        """
        return {
            "hostname": config.hostname,
            "vendor": config.vendor,
            "interfaces": config.interfaces,
            "vlans": config.vlans,
            "acls": config.acls,
            "static_routes": config.static_routes,
            "ospf": config.ospf,
            "eigrp": config.eigrp,
            "bgp": config.bgp,
            "stp": config.stp,
            "prefix_lists": config.prefix_lists,
            "route_maps": config.route_maps,
            "enable_secret": config.enable_secret,
            "domain_name": config.domain_name,
            "dns_servers": config.dns_servers,
            "ntp_servers": config.ntp_servers,
            "banner_motd": config.banner_motd,
        }

    def get_supported_vendors(self) -> list[Vendor]:
        """Get list of supported vendors.

        Returns:
            List of supported Vendor enum values
        """
        return list(self.TEMPLATE_MAP.keys())

    def generate_from_dict(self, vendor: Vendor, config_dict: dict[str, Any]) -> str:
        """Generate configuration directly from a dictionary.

        Args:
            vendor: Target vendor
            config_dict: Configuration as a dictionary

        Returns:
            Generated configuration as a string
        """
        template_name = self.TEMPLATE_MAP.get(vendor)
        if not template_name:
            raise ValueError(f"Unsupported vendor: {vendor}")

        template = self.env.get_template(template_name)
        return template.render(**config_dict)
