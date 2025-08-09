# LanWatch – Advanced Home Assistant LAN Device Tracker

LanWatch is a custom component for Home Assistant that automatically discovers and tracks devices on your local network using advanced network scanning techniques. It creates intelligent `device_tracker` entities with comprehensive device information and real-time presence detection.

## Features

- **Smart device discovery** - Automatically identifies device types and operating systems
- **Advanced fingerprinting** - Uses DHCP, mDNS, port scanning, and MAC OUI analysis
- **Real-time presence detection** - Tracks when devices connect and disconnect  
- **Rich device information** - Shows device type, OS, open ports, and network services
- **Persistent device memory** - Remembers devices even when they're offline
- **No external dependencies** - Runs entirely within Home Assistant (no Docker/MQTT needed)
- **Multiple subnet support** - Monitor devices across VLANs
- **Customizable scanning** - Configure scan intervals and timeout thresholds

## Installation

### HACS (Recommended)

1. Add this repository to HACS as a custom repository
2. Search for "LanWatch" in HACS
3. Install the integration
4. Restart Home Assistant

### Manual Installation

1. Copy the `custom_components/lanwatch` folder to your Home Assistant `config/custom_components/` directory
2. Restart Home Assistant
3. Add the integration via Settings → Devices & Services → Add Integration → LanWatch

## Configuration

During setup, you'll configure:

- **Subnets**: Network ranges to scan (e.g., `192.168.1.0/24`)
- **Scan Interval**: How often to scan in seconds (default: 60)
- **Absent After**: Seconds before marking a device as away (default: 300)

## Usage

### Entities

LanWatch creates intelligent `device_tracker` entities for each discovered device:
- **Entity ID**: `device_tracker.lanwatch_[mac_address]`
- **States**: `home` (connected) or `not_home` (disconnected)
- **Device Info**:
  - Name: Intelligently generated from DHCP/mDNS data
  - Manufacturer: Vendor identification from MAC OUI
  - Model: Device type with OS (e.g., "Phone (iOS)", "Computer (Windows)")

#### Enhanced Attributes
- **Basic Info**: `ip`, `mac`, `hostname`, `vendor`
- **Device Classification**: `device_type`, `os` 
- **Network Services**: `open_ports`, `capabilities`, `mdns_services`
- **DHCP Info**: `dhcp_hostname`, `dhcp_vendor_class`
- **Timing**: `last_seen`, `last_seen_seconds_ago`

#### Device Types Detected
- `computer` - Desktops, laptops, servers
- `phone` - Smartphones
- `tablet` - iPads, Android tablets
- `tv` - Smart TVs, streaming devices
- `speaker` - Smart speakers (Alexa, Google Home, Sonos)
- `iot` - IoT devices (ESPHome, sensors)
- `printer` - Network printers
- `nas` - Network storage devices
- `network` - Routers, switches, access points
- `media_player` - Chromecast, Apple TV
- `game_console` - PlayStation, Xbox
- `watch` - Smartwatches

#### Operating Systems Detected
- Mobile: `iOS`, `iPadOS`, `Android`
- Computer: `Windows`, `macOS`, `Linux`, `Chrome OS`
- Smart TV: `Tizen`, `webOS`, `Android TV`, `Roku OS`
- IoT: `ESPHome`, `Tasmota`, `ESP32/ESP8266`
- Other: `Alexa`, `Google Cast`, `Sonos`, `HomeKit`

### Service

Trigger an immediate scan:
```yaml
service: lanwatch.scan_now
```

### Dashboard Examples

#### Auto-Entities Card (Recommended)
Requires HACS cards: `auto-entities` and `multiple-entity-row`

```yaml
type: custom:auto-entities
card:
  type: entities
  title: LAN Devices
filter:
  include:
    - domain: device_tracker
      entity_id: /^device_tracker\.lanwatch_.*/
      options:
        type: custom:multiple-entity-row
        show_state: true
        entities:
          - attribute: ip
            name: IP
          - attribute: device_type
            name: Type
          - attribute: os
            name: OS
          - attribute: last_seen_seconds_ago
            name: Seen
            format: relative
sort:
  method: name
show_empty: false
```

#### Enhanced Markdown Table

```yaml
type: markdown
title: Network Devices
content: |
  {% set trackers = states.device_tracker 
     | selectattr('entity_id', 'match', 'device_tracker.lanwatch_.*')
     | list %}
  **Online:** {{ trackers | selectattr('state', 'eq', 'home') | list | count }} / {{ trackers | count }}
  
  | Device | Type | OS | IP | Status |
  |--------|------|----|----|--------|
  {% for d in trackers | sort(attribute='attributes.ip') %}
  | {{ d.name }} | {{ d.attributes.device_type | default('unknown') }} | {{ d.attributes.os | default('-') }} | {{ d.attributes.ip or 'N/A' }} | {{ d.state }} |
  {% endfor %}
```

#### Device Count Sensor

```yaml
template:
  - sensor:
      - name: LAN Devices Online
        state: >
          {{ states.device_tracker
             | selectattr('entity_id', 'match', 'device_tracker.lanwatch_.*')
             | selectattr('state', 'eq', 'home')
             | list | count }}
```

### Automations

#### New Device Alert with Type Detection

```yaml
automation:
  - alias: "Alert on new network device"
    trigger:
      - platform: event
        event_type: entity_registry_updated
        event_data:
          action: create
    condition:
      - condition: template
        value_template: >
          {{ trigger.event.data.entity_id.startswith('device_tracker.lanwatch_') }}
    action:
      - service: notify.mobile_app
        data:
          title: "New {{ state_attr(trigger.event.data.entity_id, 'device_type') | default('device') }} on network"
          message: >
            Device: {{ state_attr(trigger.event.data.entity_id, 'hostname') or 'Unknown' }}
            Type: {{ state_attr(trigger.event.data.entity_id, 'device_type') | default('unknown') }}
            OS: {{ state_attr(trigger.event.data.entity_id, 'os') | default('unknown') }}
            IP: {{ state_attr(trigger.event.data.entity_id, 'ip') }}
            MAC: {{ state_attr(trigger.event.data.entity_id, 'mac') }}
```

#### Device Type Filtering

```yaml
# Get all computers on the network
template:
  - sensor:
      - name: Computers Online
        state: >
          {{ states.device_tracker
             | selectattr('entity_id', 'match', 'device_tracker.lanwatch_.*')
             | selectattr('state', 'eq', 'home')
             | selectattr('attributes.device_type', 'eq', 'computer')
             | list | count }}
        attributes:
          devices: >
            {{ states.device_tracker
               | selectattr('entity_id', 'match', 'device_tracker.lanwatch_.*')
               | selectattr('state', 'eq', 'home')
               | selectattr('attributes.device_type', 'eq', 'computer')
               | map(attribute='name')
               | list }}
```

## Technical Details

### Network Discovery Methods

LanWatch uses multiple discovery techniques to gather comprehensive device information:

1. **ARP Scanning** - Primary discovery method using `scapy`
   - Sends ARP requests to all IPs in configured subnets
   - Most reliable method for finding active devices

2. **DHCP Monitoring** - Passive listening for DHCP packets
   - Captures device hostnames from DHCP requests
   - Identifies vendor class IDs for OS detection
   - Runs for 2 seconds per scan cycle

3. **mDNS/Bonjour Discovery** - Service announcement detection
   - Identifies Apple devices, Chromecast, smart speakers
   - Discovers HomeKit, AirPlay, and other services
   - Supports 24+ service types

4. **Port Scanning** - Limited TCP/UDP port probing
   - Identifies device capabilities (web, SSH, SMB, etc.)
   - Scans common ports (22, 80, 443, 445, 8080, etc.)
   - Limited to first 10 devices to minimize impact

5. **MAC OUI Analysis** - Vendor identification
   - Uses `netaddr` library for manufacturer lookup
   - Helps identify device types based on vendor

6. **DNS Resolution** - Hostname discovery
   - Standard reverse DNS lookups
   - mDNS/Avahi resolution for `.local` domains

### Device Intelligence

The component uses sophisticated fingerprinting to identify:
- Device types based on services, ports, and vendor
- Operating systems from DHCP vendor classes and mDNS
- Smart naming using DHCP hostnames and mDNS names
- Capability detection from open ports

## Performance Considerations

- **Scan Interval**: 60-120 seconds recommended for home networks
- **Absent After**: 300 seconds (5 min) prevents false "away" states for mobile devices
- **Network Impact**: 
  - ARP scanning is lightweight and non-intrusive
  - Port scanning limited to 10 devices per cycle
  - DHCP monitoring is passive (listen-only)
  - Total scan time typically under 5 seconds

## Privacy & Security

- **Local Only**: All scanning happens within your local network
- **Read-Only**: No packets modify device configuration
- **Non-Intrusive**: Uses standard network protocols
- **Data Storage**: Device information stored locally in Home Assistant
- **DHCP Monitoring**: Requires elevated privileges (may not work in all Docker setups)

## Troubleshooting

### Devices showing as "away" incorrectly
- Increase the "Absent After" timeout
- Some devices (especially mobile) may not respond to ARP when idle

### Missing devices
- Ensure the subnet configuration includes all network ranges
- Some devices may have ARP response disabled

### Permission errors
- Home Assistant needs network access for ARP scanning
- When running in Docker, use `network_mode: host`

## Development

### Running Tests

```bash
# Unit tests
pytest -q -k "not component_hass"

# Integration tests
tox -e py312-ha
```

### Contributing

Contributions are welcome! Please open an issue first to discuss changes.

## Changelog

### v0.2.0 (Latest)
- Added comprehensive device fingerprinting
- DHCP packet monitoring for hostname and OS detection
- TCP/UDP port scanning for service discovery
- Enhanced mDNS/Bonjour support (24+ service types)
- Intelligent device type classification
- Operating system detection
- Improved device naming using multiple data sources
- Added device capabilities detection
- Rich entity attributes with network service info

### v0.1.0
- Initial release
- Basic ARP scanning
- Device tracking with home/away states
- MAC vendor lookup
- Persistent device storage

## License

MIT