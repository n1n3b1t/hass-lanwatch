# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LanWatch is a Home Assistant custom component that discovers and tracks devices on local networks using ARP scanning. It works natively within Home Assistant without requiring Docker or MQTT.

## Development Commands

### Testing
```bash
# Run unit tests (excludes HA integration tests)
pytest -q -k "not component_hass"

# Run Home Assistant integration tests  
tox -e py312-ha

# Run specific test file
pytest tests/test_basic.py
```

### Linting
```bash
# Lint check with ruff
ruff check .

# Format check
ruff format --check .
```

## Architecture

### Custom Component Structure (`custom_components/lanwatch/`)

- **`__init__.py`**: Core coordinator that performs ARP scanning and manages device state
  - `LanwatchCoordinator`: DataUpdateCoordinator that scans networks periodically
  - `perform_arp_scan()`: Uses scapy for ARP discovery
  - Persistent storage via Home Assistant's Store helper
  
- **`device_tracker.py`**: Creates and manages device_tracker entities
  - `LanwatchTracker`: Entity class for each discovered device
  - Dynamic entity creation for newly discovered devices
  - Tracks home/away state based on last_seen time

- **`config_flow.py`**: UI configuration for adding the integration
  - Configures subnets, scan interval, and absent timeout

- **`const.py`**: Configuration constants and defaults

- **`manifest.json`**: Integration metadata and dependencies (scapy, netaddr)

### Key Features

1. **Device Discovery**: Scans configured subnets using ARP
2. **Persistent Storage**: Remembers devices across restarts
3. **Dynamic Entities**: Automatically creates entities for new devices
4. **Service**: `lanwatch.scan_now` for manual scans

### Entity Details

- Entity ID format: `device_tracker.lanwatch_[mac_address_no_colons]`
- States: `home` (recently seen) or `not_home` (not seen within timeout)
- Attributes: ip, hostname, mac, last_seen, vendor, last_seen_seconds_ago

### Configuration

Set during UI setup:
- `subnets`: List of network ranges to scan (e.g., ["192.168.1.0/24"])
- `interval`: Scan interval in seconds (default: 60)
- `absent_after`: Seconds before marking device away (default: 300)