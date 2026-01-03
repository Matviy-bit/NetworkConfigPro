"""Help content and documentation for the application."""

HELP_SECTIONS = {
    "getting_started": {
        "title": "Getting Started",
        "content": """
Welcome to NetConfigPro!

NetConfigPro is a network configuration generator and validator that helps
network engineers create, validate, and analyze device configurations.

QUICK START
===========

1. Generate Configuration
   - Select your target vendor (Cisco IOS, NX-OS, Arista, Juniper)
   - Fill in the configuration details using the forms
   - Click "Generate" to create the configuration
   - Review and copy/export the result

2. Import & Analyze
   - Paste an existing configuration or import from file
   - Click "Parse" to analyze the configuration
   - View the parsed elements and validation results
   - Make modifications and re-generate if needed

3. Validate Configuration
   - Any configuration (generated or imported) is automatically validated
   - Review errors, warnings, and best practice suggestions
   - Address issues before deploying to production

SUPPORTED FEATURES
==================

Layer 2 Switching:
- Switchport access/trunk modes
- Voice VLAN for IP phones
- Trunk native and allowed VLANs
- Spanning Tree (PVST, Rapid-PVST, MST)
- PortFast and BPDU Guard

Routing Protocols:
- Static routes
- OSPF (areas, passive interfaces, reference bandwidth)
- EIGRP (classic and named mode)
- BGP (neighbors, authentication, route-maps)

BGP Policy:
- Prefix lists with ge/le modifiers
- Route maps with match/set clauses
- Local preference, MED, weight, AS-path prepend

NAVIGATION
==========

Use the tabs to navigate between different sections:
- Generate: Create new configurations
- Import: Analyze existing configurations
- Diff: Compare two configurations
- Vault: Secure credential storage
- Help: This documentation

KEYBOARD SHORTCUTS
==================

Ctrl+N    New configuration
Ctrl+O    Open/Import file
Ctrl+S    Save/Export configuration
Ctrl+G    Generate configuration
Ctrl+V    Validate configuration
Ctrl+H    Show help
F1        Context-sensitive help
""",
    },

    "generate_config": {
        "title": "Generating Configurations",
        "content": """
CONFIGURATION GENERATION
========================

NetConfigPro uses templates to generate vendor-specific configurations.

SUPPORTED VENDORS
-----------------

• Cisco IOS / IOS-XE
  - Routers and switches running IOS 12.x, 15.x, or IOS-XE
  - Full support for interfaces, VLANs, ACLs, OSPF, BGP

• Cisco NX-OS
  - Nexus switches
  - Includes automatic feature enablement

• Arista EOS
  - Arista switches
  - Native EOS syntax

• Juniper Junos
  - Juniper routers and switches
  - Hierarchical set-style configuration

CONFIGURATION ELEMENTS
----------------------

Interfaces:
  - Name (e.g., GigabitEthernet0/0)
  - Description
  - IP address and subnet mask
  - Speed, duplex, MTU settings
  - Port-channel membership

Layer 2 Switching:
  - Switchport mode (access, trunk, dynamic)
  - Access VLAN assignment
  - Voice VLAN for IP phones
  - Trunk native VLAN
  - Trunk allowed VLANs
  - Channel groups with LACP modes

VLANs:
  - VLAN ID (1-4094)
  - Name and description
  - State (active/suspend)

Spanning Tree Protocol (STP):
  - Mode: PVST, Rapid-PVST, MST
  - Bridge priority configuration
  - Root primary/secondary VLANs
  - PortFast default for access ports
  - BPDU Guard default for edge ports

ACLs:
  - Standard and extended ACLs
  - Permit/deny rules with logging
  - Source and destination filtering
  - Protocol and port matching

Routing Protocols:
  - Static routes with admin distance
  - OSPF (process ID, networks, passive interfaces, reference bandwidth)
  - EIGRP (classic and named mode, AS number, networks, passive interfaces)
  - BGP (AS, neighbors, authentication, route-maps)

BGP Policy Tools:
  - Prefix Lists: Filter routes by prefix with ge/le modifiers
  - Route Maps: Apply policies with match/set clauses
    - Match: prefix-list, as-path, community
    - Set: local-preference, MED, weight, as-path prepend, community

BEST PRACTICES
--------------

1. Always add descriptions to interfaces
2. Use explicit VLAN configurations on trunks
3. Configure router-id for OSPF, EIGRP, and BGP
4. Use MD5 authentication for BGP neighbors
5. Set appropriate reference bandwidth for OSPF
6. Enable PortFast and BPDU Guard on access ports
7. Use prefix-lists for granular route filtering
8. Apply route-maps for BGP policy control
""",
    },

    "l2_switching": {
        "title": "Layer 2 Switching & STP",
        "content": """
LAYER 2 SWITCHING
=================

NetConfigPro supports comprehensive Layer 2 switching configuration
for building campus and data center networks.

SWITCHPORT MODES
----------------

Access Mode:
  - Assigns port to a single VLAN
  - Used for end-user devices, servers, printers
  - Can include voice VLAN for IP phones

  Example configuration generated:
    interface GigabitEthernet0/1
     switchport mode access
     switchport access vlan 20
     switchport voice vlan 40

Trunk Mode:
  - Carries multiple VLANs using 802.1Q tagging
  - Used for switch-to-switch and switch-to-router links
  - Configure native VLAN and allowed VLANs

  Example configuration generated:
    interface GigabitEthernet0/24
     switchport mode trunk
     switchport trunk native vlan 99
     switchport trunk allowed vlan 10,20,30,99

VOICE VLAN
----------

Voice VLAN allows a single access port to carry both:
  - Data traffic on the access VLAN
  - Voice traffic on the voice VLAN (with CoS marking)

This is essential for Cisco IP Phone deployments where the phone
connects to the switch and the PC connects through the phone.

SPANNING TREE PROTOCOL (STP)
============================

STP prevents Layer 2 loops in redundant network topologies.

STP MODES
---------

PVST+ (Per-VLAN Spanning Tree Plus):
  - Cisco proprietary
  - Separate spanning tree instance per VLAN
  - Slower convergence

Rapid-PVST+ (Recommended):
  - IEEE 802.1w based
  - Per-VLAN instances with rapid convergence
  - Default on modern Cisco switches

MST (Multiple Spanning Tree):
  - IEEE 802.1s
  - Maps multiple VLANs to fewer STP instances
  - Best for large-scale deployments

BRIDGE PRIORITY
---------------

Priority determines which switch becomes root bridge:
  - Default: 32768
  - Lower value = higher priority
  - Must be multiple of 4096 (0, 4096, 8192, etc.)
  - Use "Root Primary" for automatic lowest priority
  - Use "Root Secondary" for backup root bridge

PORTFAST & BPDU GUARD
---------------------

PortFast:
  - Skips listening/learning states
  - Immediate transition to forwarding
  - Only use on access ports (end devices)

BPDU Guard:
  - Disables port if BPDU is received
  - Protects against unauthorized switches
  - Always enable with PortFast

Example configuration generated:
  spanning-tree mode rapid-pvst
  spanning-tree vlan 1-4094 priority 4096
  spanning-tree vlan 10,20 root primary
  spanning-tree vlan 30,40 root secondary
  spanning-tree portfast default
  spanning-tree portfast bpduguard default
""",
    },

    "eigrp": {
        "title": "EIGRP Configuration",
        "content": """
EIGRP (Enhanced Interior Gateway Routing Protocol)
===================================================

EIGRP is a Cisco-developed advanced distance vector routing protocol
with fast convergence and efficient bandwidth usage.

CLASSIC EIGRP MODE
------------------

Traditional EIGRP configuration using AS number:

  router eigrp 100
   eigrp router-id 10.0.0.1
   no auto-summary
   network 10.0.0.0 0.255.255.255
   network 192.168.1.0 0.0.0.255
   passive-interface GigabitEthernet0/1

Configuration options:
  - AS Number (1-65535): Must match on all EIGRP neighbors
  - Router ID: Unique identifier (use loopback IP)
  - Networks: Specify with wildcard masks
  - Passive Interfaces: Don't send EIGRP on these interfaces

NAMED EIGRP MODE
----------------

Modern configuration style with address-family structure:

  router eigrp CAMPUS
   address-family ipv4 unicast autonomous-system 100
    eigrp router-id 10.0.0.1
    network 10.0.0.0 0.255.255.255
    passive-interface GigabitEthernet0/1
    exit-address-family

Advantages of Named Mode:
  - Cleaner configuration hierarchy
  - Per-interface configuration under address-family
  - Required for advanced features in newer IOS versions
  - Better IPv4/IPv6 feature parity

WHEN TO USE EIGRP
-----------------

Ideal for:
  - Cisco-only environments
  - Campus and enterprise networks
  - Quick convergence requirements
  - Hub-and-spoke topologies

Considerations:
  - Cisco proprietary (now open standard)
  - Works with DMVPN and SD-WAN
  - Simpler than OSPF for basic deployments

NETWORK STATEMENTS
------------------

Use wildcard masks to match interfaces:

  10.0.0.0 0.255.255.255     - All 10.x.x.x networks
  192.168.1.0 0.0.0.255      - Single /24 network
  172.16.0.0 0.0.255.255     - 172.16.0.0/16

PASSIVE INTERFACES
------------------

Mark interfaces that should participate in EIGRP routing
but not send EIGRP packets (e.g., user-facing ports):

  passive-interface GigabitEthernet0/1
  passive-interface Vlan20
""",
    },

    "bgp_policy": {
        "title": "BGP Policy (Prefix Lists & Route Maps)",
        "content": """
BGP POLICY CONFIGURATION
========================

NetConfigPro supports comprehensive BGP policy tools for
controlling route advertisement and path selection.

PREFIX LISTS
============

Prefix lists filter routes based on network prefixes.

BASIC SYNTAX
------------

  ip prefix-list NAME seq SEQ ACTION PREFIX

Examples:
  ip prefix-list ALLOWED seq 10 permit 10.0.0.0/8
  ip prefix-list DENIED seq 10 deny 0.0.0.0/0

GE/LE MODIFIERS
---------------

ge (greater-than-or-equal): Minimum prefix length
le (less-than-or-equal): Maximum prefix length

Examples:
  10.0.0.0/8 ge 16 le 24
    Matches: 10.0.0.0/16, 10.1.0.0/24, 10.255.255.0/24
    Rejects: 10.0.0.0/8, 10.0.0.0/25

  0.0.0.0/0 le 32
    Matches: Any prefix (use for implicit deny)

COMMON USE CASES
----------------

Allow only your prefixes:
  ip prefix-list MY-NETS seq 10 permit 192.168.0.0/16 le 24
  ip prefix-list MY-NETS seq 100 deny 0.0.0.0/0 le 32

Block default route:
  ip prefix-list NO-DEFAULT seq 10 deny 0.0.0.0/0
  ip prefix-list NO-DEFAULT seq 20 permit 0.0.0.0/0 le 32

ROUTE MAPS
==========

Route maps apply policy by matching conditions and setting attributes.

STRUCTURE
---------

  route-map NAME permit|deny SEQUENCE
   match CONDITION
   set ATTRIBUTE

MATCH CLAUSES
-------------

match ip address prefix-list NAME
  - Match routes against a prefix list

match as-path ACCESS-LIST-NAME
  - Match BGP AS path

match community COMMUNITY-LIST
  - Match BGP communities

SET CLAUSES
-----------

set local-preference VALUE
  - Influence outbound path selection (higher = preferred)
  - Default: 100
  - Only for iBGP

set metric VALUE (MED)
  - Influence inbound path selection
  - Lower = preferred
  - Sent to eBGP neighbors

set weight VALUE
  - Local-only path preference (highest = preferred)
  - Default: 0 (32768 for locally originated)
  - Not advertised to neighbors

set as-path prepend AS AS AS
  - Make path appear longer
  - Influence inbound traffic from neighbors

set community VALUE
  - Tag routes for policy decisions

EXAMPLE CONFIGURATION
---------------------

Prefer routes from one ISP over another:

  ip prefix-list ANY seq 10 permit 0.0.0.0/0 le 32

  route-map ISP-A-IN permit 10
   match ip address prefix-list ANY
   set local-preference 200

  route-map ISP-B-IN permit 10
   match ip address prefix-list ANY
   set local-preference 100

  router bgp 65001
   neighbor 10.1.1.1 route-map ISP-A-IN in
   neighbor 10.2.2.2 route-map ISP-B-IN in

APPLYING ROUTE MAPS
-------------------

On BGP neighbors:
  neighbor X.X.X.X route-map NAME in   - Inbound filtering
  neighbor X.X.X.X route-map NAME out  - Outbound filtering

On redistribution:
  redistribute ospf 1 route-map OSPF-TO-BGP
""",
    },

    "import_config": {
        "title": "Importing Configurations",
        "content": """
IMPORTING EXISTING CONFIGURATIONS
=================================

NetConfigPro can parse and analyze existing network configurations.

SUPPORTED FORMATS
-----------------

Currently supported:
• Cisco IOS / IOS-XE running configuration
• Cisco NX-OS running configuration (basic parsing)

Coming soon:
• Arista EOS
• Juniper Junos
• Cisco ASA

HOW TO IMPORT
-------------

1. Copy the configuration from your device:
   - SSH to device
   - Run "show running-config"
   - Copy the output

2. In NetConfigPro:
   - Go to the "Import" section
   - Paste the configuration in the text area
   - Or click "Open File" to import from a file
   - Click "Parse Configuration"

3. Review the results:
   - Parsed elements are shown in structured form
   - Validation issues are highlighted
   - Unknown elements are flagged for review

IMPORT SYSLOG FILE
------------------

You can also import syslog files to analyze device logs:

1. Click "Import Syslog File" button
2. Select a .log or .txt file
3. The file contents load into the text area
4. A summary appears showing:
   - Total lines in the file
   - Message counts by severity level:
     EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG
   - Parsed vs unparsed line counts

This is useful for:
• Reviewing device events and errors
• Troubleshooting network issues
• Analyzing log patterns
• Extracting configuration snippets from logs

WHAT GETS PARSED
----------------

The parser extracts:
• Hostname and domain configuration
• Interface configurations
• VLAN definitions
• Access control lists
• Static routes
• OSPF configuration
• BGP configuration
• DNS and NTP servers
• Banner messages

AFTER IMPORT
------------

Once imported, you can:
• View the structured configuration
• Run validation checks
• Convert to a different vendor format
• Export the parsed configuration
• Modify and regenerate
""",
    },

    "diff_config": {
        "title": "Configuration Diff",
        "content": """
CONFIGURATION COMPARISON (DIFF)
===============================

The Diff tab allows you to compare two configurations side-by-side
to see what has changed between them.

HOW TO USE
----------

1. Go to the "Diff" tab
2. Paste the original configuration in "Configuration A"
3. Paste the modified configuration in "Configuration B"
4. Click "Compare"

UNDERSTANDING THE OUTPUT
------------------------

The diff output uses standard unified diff format:

  Lines starting with "-" (red)
    - Present in Configuration A but removed in B

  Lines starting with "+" (green)
    - Added in Configuration B (not in A)

  Lines without prefix
    - Unchanged between both configurations

  @@ markers
    - Show line numbers and context location

DIFF STATISTICS
---------------

After comparison, you'll see statistics showing:
• Number of lines added
• Number of lines removed
• Total changes

USE CASES
---------

Before/After Changes:
  Compare config before and after making changes to see
  exactly what was modified.

Audit Compliance:
  Compare current config against a known-good baseline
  to detect unauthorized changes.

Migration Planning:
  Compare configs between old and new devices to plan
  migration steps.

Troubleshooting:
  Compare working vs non-working configs to identify
  the difference causing issues.

Peer Review:
  Review proposed changes by comparing against
  the current production config.

TIPS
----

• Use "Clear" to reset both text areas
• Larger configs may take a moment to compare
• Results show context around changes for clarity
• Copy the diff output for documentation
""",
    },

    "validation": {
        "title": "Configuration Validation",
        "content": """
CONFIGURATION VALIDATION
========================

NetConfigPro performs comprehensive validation to catch errors and
suggest improvements before you deploy configurations.

SEVERITY LEVELS
---------------

ERROR (✗)
  - Must be fixed before deployment
  - Syntax errors, invalid values
  - Duplicate configurations that will fail

WARNING (⚠)
  - Should be reviewed
  - Security concerns
  - Potential issues

INFO (ℹ)
  - Best practice suggestions
  - Documentation recommendations
  - Optimization opportunities

VALIDATION CATEGORIES
---------------------

Syntax:
  - Valid IP addresses and subnet masks
  - Correct VLAN ranges (1-4094)
  - Valid hostname format
  - Correct MTU values

Security:
  - Weak password detection
  - Missing BGP authentication
  - Trunk ports allowing all VLANs
  - No enable secret configured

Best Practice:
  - Missing interface descriptions
  - No NTP/DNS servers
  - Generic VLAN names
  - Implicit deny in ACLs

Redundancy:
  - Duplicate IP addresses
  - Duplicate VLAN definitions
  - Duplicate ACL sequences
  - Duplicate static routes

Performance:
  - Low OSPF reference bandwidth
  - Suboptimal MTU settings

VALIDATION RULES
----------------

Interfaces:
  - Unique IP addresses
  - Valid subnet masks
  - Descriptions on routed interfaces
  - Explicit trunk VLAN configuration

VLANs:
  - No reserved VLAN usage (1, 1002-1005)
  - Descriptive VLAN names
  - No duplicate VLAN IDs

Routing:
  - Explicit router-id configuration
  - BGP neighbor authentication
  - Valid next-hop addresses

Global:
  - Strong enable secrets
  - NTP configuration
  - DNS configuration
  - Login banner
""",
    },

    "security": {
        "title": "Security & Vault",
        "content": """
SECURITY FEATURES
=================

NetConfigPro takes security seriously. Sensitive data is always
encrypted and never stored in plaintext.

SECURE VAULT
------------

The vault stores sensitive information encrypted using:
• AES-256 encryption (Fernet)
• PBKDF2 key derivation with 480,000 iterations
• Unique salt per vault
• Secure file permissions (600)

What can be stored:
• Device credentials (username/password)
• SNMP community strings
• BGP MD5 passwords
• Custom template variables
• API keys and tokens

CREATING A VAULT
----------------

1. Go to Settings > Vault
2. Click "Create Vault"
3. Enter a strong master password (8+ characters)
4. Confirm the password
5. The vault is now ready to use

IMPORTANT: Remember your master password!
There is no recovery option if you forget it.

USING THE VAULT
---------------

Storing credentials:
1. Unlock the vault with your master password
2. Click "Add Credential"
3. Enter name, username, and password
4. Click Save

Using credentials:
• Vault variables can be referenced in templates
• Format: {{ vault.credential_name.password }}
• Values are decrypted only when needed

SECURITY BEST PRACTICES
-----------------------

1. Use a strong master password
2. Lock the vault when not in use
3. Don't share vault files
4. Regularly rotate stored passwords
5. Use unique credentials per device/service

DATA PRIVACY
------------

• All sensitive data is encrypted at rest
• Decrypted data only exists in memory
• No data is sent to external servers
• Vault file uses restrictive permissions
• Master password is never stored
""",
    },

    "keyboard_shortcuts": {
        "title": "Keyboard Shortcuts",
        "content": """
KEYBOARD SHORTCUTS
==================

GENERAL
-------

Ctrl+N        Create new configuration
Ctrl+O        Open/Import configuration file
Ctrl+S        Save/Export current configuration
Ctrl+W        Close current tab
Ctrl+Q        Quit application
F1            Open help
Escape        Cancel current operation

EDITING
-------

Ctrl+Z        Undo
Ctrl+Y        Redo
Ctrl+A        Select all
Ctrl+C        Copy
Ctrl+X        Cut
Ctrl+V        Paste
Ctrl+F        Find in configuration

GENERATION & VALIDATION
-----------------------

Ctrl+G        Generate configuration
Ctrl+Shift+V  Validate configuration
Ctrl+D        Show diff view
Ctrl+P        Parse imported configuration

NAVIGATION
----------

Ctrl+1        Go to Generate tab
Ctrl+2        Go to Import tab
Ctrl+3        Go to Validate tab
Ctrl+4        Go to Vault tab
Ctrl+Tab      Next tab
Ctrl+Shift+Tab Previous tab

VAULT
-----

Ctrl+L        Lock vault
Ctrl+U        Unlock vault
""",
    },

    "troubleshooting": {
        "title": "Troubleshooting",
        "content": """
TROUBLESHOOTING
===============

COMMON ISSUES
-------------

Configuration won't generate:
  - Check that all required fields are filled
  - Verify IP addresses are valid format
  - Ensure VLAN IDs are in range 1-4094
  - Check for duplicate values

Parser doesn't recognize my config:
  - Ensure it's a full running configuration
  - Check vendor detection (should start with 'hostname')
  - Try specifying vendor manually
  - Some features may not be parsed yet

Vault won't unlock:
  - Verify you're using the correct password
  - Ensure the vault file isn't corrupted
  - Check file permissions on vault.enc
  - Try creating a new vault if needed

Application crashes on startup:
  - Check Python version (3.10+ required)
  - Verify all dependencies are installed
  - Check for conflicting packages
  - Try reinstalling requirements

GETTING HELP
------------

If you encounter issues:

1. Check this help documentation
2. Review the error message carefully
3. Check the application logs
4. Report issues on GitHub

LOG FILES
---------

Logs are stored in:
  ~/.netconfigpro/logs/

Include log files when reporting issues.

REPORTING BUGS
--------------

When reporting bugs, please include:
  - Steps to reproduce the issue
  - Expected vs actual behavior
  - Configuration sample (sanitized)
  - Error messages
  - Application version
  - Operating system

CONTACT
-------

For support and bug reports:
  - GitHub Issues: github.com/netconfigpro/issues
  - Email: support@netconfigpro.example.com
""",
    },
}


def get_help_section(section_id: str) -> dict:
    """Get a specific help section."""
    return HELP_SECTIONS.get(section_id, {})


def get_all_sections() -> dict:
    """Get all help sections."""
    return HELP_SECTIONS


def get_section_titles() -> list[tuple[str, str]]:
    """Get list of (id, title) for all sections."""
    return [(k, v["title"]) for k, v in HELP_SECTIONS.items()]
