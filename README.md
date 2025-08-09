<div align="center">

# 🔍 LanWatch

### Advanced Network Discovery & Device Tracking for Home Assistant

[![Home Assistant](https://img.shields.io/badge/Home%20Assistant-Custom%20Component-41BDF5?style=for-the-badge&logo=homeassistant)](https://www.home-assistant.io/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/yourusername/hass-lanwatch/ci.yml?style=for-the-badge&label=Tests)](https://github.com/yourusername/hass-lanwatch/actions)
[![HACS](https://img.shields.io/badge/HACS-Default-41BDF5?style=for-the-badge)](https://github.com/hacs/integration)

**Automatically discover and intelligently track every device on your network with zero configuration**

[Features](#-features) • [Installation](#-installation) • [Configuration](#-configuration) • [Examples](#-examples) • [FAQ](#-faq)

</div>

---

## 🎯 What is LanWatch?

LanWatch transforms Home Assistant into a powerful network monitoring hub. It automatically discovers devices on your local network, identifies what they are, and tracks their presence in real-time—all without external dependencies like Docker or MQTT.

### 🚀 Key Highlights

- **🧠 Smart Device Recognition** – Automatically identifies phones, computers, IoT devices, smart TVs, and more
- **🔐 Privacy-First** – All scanning happens locally, no cloud services required  
- **⚡ Real-Time Tracking** – Know instantly when devices connect or disconnect
- **📊 Rich Data** – Detailed device info including OS, open ports, and network services
- **🎮 Zero Config** – Works out of the box with intelligent defaults
- **🏠 Multi-Network** – Monitor devices across VLANs and subnets

## ✨ Features

### 🔎 Advanced Discovery Engine
- **6 Detection Methods** – ARP, DHCP, mDNS, Port Scanning, MAC OUI, DNS
- **Smart Fingerprinting** – Combines multiple data sources for accurate identification
- **Service Discovery** – Detects 24+ network services (HomeKit, Chromecast, Sonos, etc.)

### 📱 Device Intelligence
<details>
<summary><b>12 Device Types Detected</b></summary>

| Type | Examples |
|------|----------|
| 📱 **Phone** | iPhone, Android phones |
| 💻 **Computer** | Windows PCs, Macs, Linux servers |
| 📺 **TV** | Smart TVs, Apple TV, Roku |
| 🔊 **Speaker** | Alexa, Google Home, Sonos |
| 🎮 **Game Console** | PlayStation, Xbox, Switch |
| 🖨️ **Printer** | Network printers, scanners |
| 💾 **NAS** | Synology, QNAP, UnRAID |
| 🌐 **Network** | Routers, switches, APs |
| 🏠 **IoT** | ESPHome, Tasmota devices |
| ⌚ **Watch** | Apple Watch, Galaxy Watch |
| 📟 **Tablet** | iPad, Android tablets |
| 📡 **Media Player** | Chromecast, streaming boxes |

</details>

<details>
<summary><b>Operating Systems Identified</b></summary>

- **Mobile:** iOS, iPadOS, Android, Wear OS
- **Desktop:** Windows, macOS, Linux, Chrome OS
- **TV/Media:** Tizen, webOS, Android TV, Roku OS
- **IoT:** ESPHome, Tasmota, HomeKit, Matter
- **Voice:** Alexa OS, Google Cast

</details>

### 🏃 Performance & Reliability
- **Lightweight** – Typical scan completes in <5 seconds
- **Non-Intrusive** – Uses standard protocols, no device modification
- **Persistent Storage** – Remembers devices across restarts
- **Smart Caching** – Reduces network traffic with intelligent polling

## 📦 Installation

### Method 1: HACS (Recommended)

[![Open your Home Assistant instance and open a repository inside HACS.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=yourusername&repository=hass-lanwatch&category=integration)

1. Click the button above OR manually add repository in HACS
2. Search for "**LanWatch**" in HACS
3. Click Install
4. Restart Home Assistant
5. Add integration: **Settings** → **Devices & Services** → **+ Add Integration** → **LanWatch**

### Method 2: Manual Installation

```bash
# Navigate to your Home Assistant config directory
cd /config

# Create custom_components directory if it doesn't exist
mkdir -p custom_components

# Download and extract LanWatch
cd custom_components
git clone https://github.com/yourusername/hass-lanwatch.git
mv hass-lanwatch/custom_components/lanwatch .
rm -rf hass-lanwatch

# Restart Home Assistant
```

## ⚙️ Configuration

### Quick Start (UI)

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=lanwatch)

During setup, you'll configure:

| Setting | Default | Description |
|---------|---------|-------------|
| **Subnets** | `192.168.1.0/24` | Networks to scan (comma-separated) |
| **Scan Interval** | `60` seconds | How often to check for devices |
| **Absent After** | `300` seconds | Time before marking device as away |

## 📊 Examples

### 🎨 Dashboard Cards

<details>
<summary><b>Beautiful Auto-Entities Card</b></summary>

> Requires: `auto-entities` and `multiple-entity-row` from HACS

```yaml
type: custom:auto-entities
card:
  type: entities
  title: 🌐 Network Devices
  card_mod:
    style: |
      ha-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      }
filter:
  include:
    - domain: device_tracker
      entity_id: /^device_tracker\.lanwatch_.*/
      options:
        type: custom:multiple-entity-row
        show_state: true
        secondary_info: last-changed
        entities:
          - attribute: device_type
            name: Type
            styles:
              width: 60px
          - attribute: os
            name: OS
            styles:
              width: 80px
          - attribute: ip
            name: IP
            styles:
              width: 100px
sort:
  method: state
  reverse: false
show_empty: false
```

</details>

<details>
<summary><b>Device Statistics Card</b></summary>

```yaml
type: vertical-stack
cards:
  - type: custom:mini-graph-card
    name: Network Devices Online
    entities:
      - entity: sensor.lan_devices_online
        color: '#44739e'
    hours_to_show: 24
    points_per_hour: 4
    line_width: 2
    animate: true
    
  - type: horizontal-stack
    cards:
      - type: custom:button-card
        template: sensor_button
        entity: sensor.computers_online
        name: Computers
        icon: mdi:laptop
        
      - type: custom:button-card
        template: sensor_button
        entity: sensor.phones_online
        name: Phones
        icon: mdi:cellphone
        
      - type: custom:button-card
        template: sensor_button
        entity: sensor.iot_devices_online
        name: IoT Devices
        icon: mdi:chip
```

</details>

### 🤖 Automations

<details>
<summary><b>Smart New Device Alert</b></summary>

```yaml
automation:
  - alias: "🔔 New Device on Network"
    trigger:
      - platform: event
        event_type: entity_registry_updated
        event_data:
          action: create
    condition:
      - "{{ trigger.event.data.entity_id.startswith('device_tracker.lanwatch_') }}"
    action:
      - service: notify.mobile_app
        data:
          title: "🆕 New {{ state_attr(trigger.event.data.entity_id, 'device_type') | title }}"
          message: |
            📱 {{ state_attr(trigger.event.data.entity_id, 'hostname') or 'Unknown Device' }}
            🏷️ {{ state_attr(trigger.event.data.entity_id, 'vendor') }}
            🌐 {{ state_attr(trigger.event.data.entity_id, 'ip') }}
          data:
            image: >
              {% set dtype = state_attr(trigger.event.data.entity_id, 'device_type') %}
              {% if dtype == 'phone' %}/local/images/phone.png
              {% elif dtype == 'computer' %}/local/images/laptop.png
              {% else %}/local/images/device.png{% endif %}
```

</details>

<details>
<summary><b>Guest WiFi Monitor</b></summary>

```yaml
automation:
  - alias: "Guest Network Activity"
    trigger:
      - platform: state
        entity_id: device_tracker.lanwatch_unknown_device
        to: 'home'
    condition:
      - "{{ '192.168.50.' in state_attr(trigger.entity_id, 'ip') }}"
    action:
      - service: notify.admin
        data:
          title: "👥 Guest Network Access"
          message: "Device connected to guest WiFi"
```

</details>

### 📈 Template Sensors

<details>
<summary><b>Device Counters by Type</b></summary>

```yaml
template:
  - sensor:
      - name: "LAN Devices Online"
        unique_id: lan_devices_online
        state: >
          {{ states.device_tracker
             | selectattr('entity_id', 'match', 'device_tracker.lanwatch_.*')
             | selectattr('state', 'eq', 'home')
             | list | count }}
        icon: mdi:lan
        
      - name: "Computers Online"
        unique_id: computers_online
        state: >
          {{ states.device_tracker
             | selectattr('entity_id', 'match', 'device_tracker.lanwatch_.*')
             | selectattr('state', 'eq', 'home')
             | selectattr('attributes.device_type', 'defined')
             | selectattr('attributes.device_type', 'eq', 'computer')
             | list | count }}
        icon: mdi:laptop
        attributes:
          devices: >
            {{ states.device_tracker
               | selectattr('entity_id', 'match', 'device_tracker.lanwatch_.*')
               | selectattr('state', 'eq', 'home')
               | selectattr('attributes.device_type', 'defined')
               | selectattr('attributes.device_type', 'eq', 'computer')
               | map(attribute='name') | list | join(', ') }}
```

</details>

### 🔧 Services

```yaml
# Trigger immediate network scan
service: lanwatch.scan_now

# Use in scripts/automations
script:
  refresh_network:
    sequence:
      - service: lanwatch.scan_now
      - delay: '00:00:05'
      - service: notify.mobile_app
        data:
          message: "Network scan complete!"
```


## 🔬 How It Works

<details>
<summary><b>6 Discovery Methods Working Together</b></summary>

| Method | Purpose | Details |
|--------|---------|---------|
| **ARP Scanning** | Primary discovery | Sends requests to all subnet IPs |
| **DHCP Monitoring** | Hostname & OS detection | Passive listening for 2 seconds |
| **mDNS/Bonjour** | Service discovery | 24+ service types (HomeKit, AirPlay, etc.) |
| **Port Scanning** | Capability detection | Limited to 10 devices/cycle |
| **MAC OUI Lookup** | Vendor identification | Uses netaddr library |
| **DNS Resolution** | Hostname discovery | Reverse DNS + mDNS |

</details>

## ❓ FAQ

<details>
<summary><b>Why are some devices showing as "away" when they're connected?</b></summary>

Mobile devices often enter power-saving modes. Try:
- Increasing "Absent After" to 600 seconds (10 minutes)
- Ensuring WiFi power saving is disabled on critical devices
- Using static IP assignments for important devices

</details>

<details>
<summary><b>Can LanWatch work with VLANs?</b></summary>

Yes! Configure multiple subnets during setup:
```
192.168.1.0/24, 192.168.50.0/24, 10.0.0.0/24
```

</details>

<details>
<summary><b>Does it work in Docker?</b></summary>

Yes, but requires `network_mode: host` for ARP scanning to work properly.

</details>

<details>
<summary><b>How much network traffic does it generate?</b></summary>

Minimal. A typical scan:
- Takes <5 seconds
- Sends ~250 ARP packets (for /24 network)
- Port scans only 10 devices
- Total bandwidth: <100KB per scan

</details>

<details>
<summary><b>Can I exclude specific devices?</b></summary>

Not directly, but you can:
1. Disable entities you don't want to track
2. Use different subnets for guest devices
3. Filter devices in your dashboards

</details>

## 🚀 Roadmap

- [ ] **v0.3.0** - Wake-on-LAN support
- [ ] **v0.4.0** - Historical statistics & graphs
- [ ] **v0.5.0** - Device grouping & families
- [ ] **v1.0.0** - Full HACS default repository

## 🤝 Contributing

We love contributions! Please:

1. 🐛 **Report bugs** via [Issues](https://github.com/yourusername/hass-lanwatch/issues)
2. 💡 **Suggest features** in [Discussions](https://github.com/yourusername/hass-lanwatch/discussions)
3. 🔧 **Submit PRs** for bug fixes and features

### Development Setup

```bash
# Clone the repo
git clone https://github.com/yourusername/hass-lanwatch.git
cd hass-lanwatch

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest -q -k "not component_hass"  # Unit tests
tox -e py312-ha                     # HA integration tests

# Lint code
ruff check .
ruff format --check .
```

## 📝 Changelog

<details>
<summary><b>Version History</b></summary>

### **v0.2.0** (2024-01) 🎉
- ✨ Advanced device fingerprinting (12 types, 15+ OSes)
- 🔍 DHCP packet monitoring for better identification
- 🌐 Port scanning for service discovery
- 📡 Enhanced mDNS support (24+ services)
- 🧠 Intelligent device naming from multiple sources
- 📊 Rich entity attributes

### **v0.1.0** (2023-12)
- 🚀 Initial release
- 📡 Basic ARP scanning
- 🏠 Home/away tracking
- 💾 Persistent storage

</details>

## 📄 License

MIT © 2024 - See [LICENSE](LICENSE) file

---

<div align="center">

### Made with ❤️ for the Home Assistant Community

**[⭐ Star this repo](https://github.com/yourusername/hass-lanwatch)** if you find it useful!

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A-Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/yourusername)
[![PayPal](https://img.shields.io/badge/PayPal-Donate-00457C?style=for-the-badge&logo=paypal)](https://paypal.me/yourusername)

[Report Bug](https://github.com/yourusername/hass-lanwatch/issues) · [Request Feature](https://github.com/yourusername/hass-lanwatch/discussions) · [Documentation](https://github.com/yourusername/hass-lanwatch/wiki)

</div>