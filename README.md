# LanWatch – Native Home Assistant LAN Device Tracker

LanWatch is a custom component for Home Assistant that automatically discovers and tracks devices on your local network using ARP scanning. It creates `device_tracker` entities for each discovered device with real-time presence detection.

## Features

- **Automatic device discovery** - Scans your network and creates entities for all devices
- **Real-time presence detection** - Tracks when devices connect and disconnect  
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

LanWatch creates `device_tracker` entities for each discovered device:
- Entity ID: `device_tracker.lanwatch_[mac_address]`
- States: `home` (connected) or `not_home` (disconnected)
- Attributes: IP address, hostname, MAC address, last seen time, vendor

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
          - attribute: hostname
            name: Host
          - attribute: last_seen_seconds_ago
            name: Seen
            format: relative
sort:
  method: name
show_empty: false
```

#### Simple Markdown Table

```yaml
type: markdown
title: Network Devices
content: |
  {% set trackers = states.device_tracker 
     | selectattr('entity_id', 'match', 'device_tracker.lanwatch_.*')
     | list %}
  **Online:** {{ trackers | selectattr('state', 'eq', 'home') | list | count }} / {{ trackers | count }}
  
  | Device | IP | Status |
  |--------|-----|--------|
  {% for d in trackers | sort(attribute='attributes.ip') %}
  | {{ d.name }} | {{ d.attributes.ip or 'N/A' }} | {{ d.state }} |
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

#### New Device Alert

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
          title: "New device on network"
          message: >
            New device detected: {{ state_attr(trigger.event.data.entity_id, 'hostname') or 'Unknown' }}
            MAC: {{ state_attr(trigger.event.data.entity_id, 'mac') }}
```

## Technical Details

- Uses ARP (Address Resolution Protocol) scanning via `scapy`
- Stores device information persistently in Home Assistant's storage
- Automatically creates entities for newly discovered devices
- Tracks devices by MAC address for consistent identification
- Performs reverse DNS lookups for device hostnames

## Performance Considerations

- **Scan Interval**: 60-120 seconds recommended for home networks
- **Absent After**: 300 seconds (5 min) prevents false "away" states for mobile devices
- **Network Impact**: ARP scanning is lightweight and non-intrusive

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

## License

MIT