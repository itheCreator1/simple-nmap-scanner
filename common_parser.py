#!/usr/bin/env python3
"""
Common XML Parsing Utilities
============================

Shared functions for all nmap XML parsers to handle errors gracefully
and provide consistent error messages.

This module provides:
- Safe XML reading from stdin with error handling
- Helper functions for element/attribute extraction
- Consistent error messaging across all parsers
"""

import sys
import xml.etree.ElementTree as ET
from typing import Optional, Any


def read_and_parse_xml() -> Optional[ET.Element]:
    """
    Read XML from stdin and parse it safely.

    Returns:
        Parsed XML root element, or None on error

    Error Handling:
        Prints detailed error messages to stderr explaining common causes
    """
    try:
        xml_string = sys.stdin.read()

        if not xml_string.strip():
            print("ERROR: No XML input received", file=sys.stderr)
            print("", file=sys.stderr)
            print("Possible causes:", file=sys.stderr)
            print("  - Nmap did not run (check if nmap command failed)", file=sys.stderr)
            print("  - Empty scan results", file=sys.stderr)
            print("  - Piping error in shell script", file=sys.stderr)
            print("", file=sys.stderr)
            print("Try running the nmap command directly to see the error", file=sys.stderr)
            return None

        root = ET.fromstring(xml_string)
        return root

    except ET.ParseError as e:
        print(f"ERROR: Invalid XML from nmap: {e}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Possible causes:", file=sys.stderr)
        print("  - Nmap was killed mid-execution (Ctrl+C or timeout)", file=sys.stderr)
        print("  - Insufficient permissions (try running with sudo)", file=sys.stderr)
        print("  - Network timeout during scan", file=sys.stderr)
        print("  - Corrupted output stream", file=sys.stderr)
        print("", file=sys.stderr)
        print("Suggestions:", file=sys.stderr)
        print("  - Check that nmap completed successfully", file=sys.stderr)
        print("  - Try running with sudo if scanning network", file=sys.stderr)
        print("  - Increase timeout values if network is slow", file=sys.stderr)
        return None

    except Exception as e:
        print(f"ERROR: Unexpected error while parsing XML: {e}", file=sys.stderr)
        print(f"Error type: {type(e).__name__}", file=sys.stderr)
        return None


def safe_get_attrib(element: Optional[ET.Element], key: str, default: str = "N/A") -> str:
    """
    Safely get attribute value from XML element with default fallback.

    Args:
        element: XML element (can be None)
        key: Attribute key to retrieve
        default: Default value if element is None or key doesn't exist

    Returns:
        Attribute value or default
    """
    if element is None:
        return default
    return element.attrib.get(key, default)


def safe_find_text(element: ET.Element, path: str, default: str = "N/A") -> str:
    """
    Safely find element and get its text with default fallback.

    Args:
        element: XML element to search within
        path: XPath to search for
        default: Default value if element not found or has no text

    Returns:
        Element text or default
    """
    found = element.find(path)
    if found is None:
        return default
    return found.text if found.text else default


def safe_find(element: ET.Element, path: str) -> Optional[ET.Element]:
    """
    Safely find element, returning None instead of raising exception.

    Args:
        element: XML element to search within
        path: XPath to search for

    Returns:
        Found element or None
    """
    try:
        return element.find(path)
    except Exception:
        return None


def has_valid_ports(root: ET.Element) -> bool:
    """
    Check if XML contains valid port data.

    Args:
        root: XML root element

    Returns:
        True if ports element exists and has data
    """
    for host in root.findall('host'):
        ports_elem = host.find('ports')
        if ports_elem is not None and len(ports_elem.findall('port')) > 0:
            return True
    return False


def get_host_count(root: ET.Element) -> int:
    """
    Get count of hosts in scan results.

    Args:
        root: XML root element

    Returns:
        Number of host elements found
    """
    return len(root.findall('host'))


def print_parser_header(parser_name: str):
    """
    Print consistent header for parser output.

    Args:
        parser_name: Name of the parser (e.g., "Active Host Discovery")
    """
    print(f"\n{parser_name}")
    print("=" * len(parser_name))


def print_no_results_message(item_type: str = "results"):
    """
    Print consistent "no results" message.

    Args:
        item_type: Type of items expected (hosts, ports, services, etc.)
    """
    print(f"\nNo {item_type} found.")
    print("This could mean:")
    print(f"  - No {item_type} discovered in scan")
    print("  - All items filtered out")
    print("  - Scan target was unreachable")
