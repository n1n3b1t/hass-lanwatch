## LanWatch – Lightweight LAN device tracker via MQTT Discovery

LanWatch scans your LAN using ARP, publishes Home Assistant MQTT Discovery for each MAC as a `device_tracker`, and keeps attributes like IP, hostname, and last_seen updated. It’s fast, modern, and runs alongside Home Assistant.

### 1) Drop-in Docker service

Add this service next to Home Assistant in your `docker-compose.yml`:

```yaml
services:
  lanwatch:
    image: ghcr.io/your-org/lanwatch:latest  # or build locally from this repo
    container_name: lanwatch
    network_mode: host                    # sees your LAN & mDNS/broadcast
    restart: unless-stopped
    environment:
      MQTT_HOST: 127.0.0.1
      MQTT_PORT: 1883
      MQTT_USER: ""                       # set if you use auth
      MQTT_PASS: ""                       # set if you use auth
      SUBNETS: "192.168.1.0/24"          # comma-separate for more
      INTERVAL_SEC: "60"                  # scan every N seconds
      ABSENT_AFTER_SEC: "300"            # mark away if unseen for N sec
      DISCOVERY_PREFIX: "homeassistant"
      TOPIC_PREFIX: "lanwatch"
      NAME_PREFIX: "LAN"
    volumes:
      - ./config/lanwatch_cache.json:/app/lanwatch_cache.json   # persistence (optional)
```

Create the folder:

```bash
mkdir -p lanwatch
```

### 2) The LanWatch script

Save as `lanwatch/lanwatch.py`. The script is already included in this repo.

Bring it up:

```bash
docker compose up -d lanwatch
```

Home Assistant will auto-create `device_tracker.lan_*` entities within ~1 minute.

### 3) Optional: a count sensor + “Scan now” button

Count sensor (HA YAML):

```yaml
template:
  - sensor:
      - name: LanWatch Online Count
        state: >
          {{ expand(integration_entities('mqtt'))
             | selectattr('domain','eq','device_tracker')
             | selectattr('state','eq','home')
             | list | count }}
```

“Scan now” button (call MQTT topic):

```yaml
type: button
name: Scan now
tap_action:
  action: call-service
  service: mqtt.publish
  data:
    topic: lanwatch/control/scan_now
```

### 4) Dashboard cards

A) Auto-Entities (live list with IP + last seen) — recommended

(Requires HACS: auto-entities and multiple-entity-row)

```yaml
type: custom:auto-entities
card:
  type: entities
  title: LAN Devices
  show_header_toggle: false
filter:
  include:
    - domain: device_tracker
      entity_id: /^device_tracker\.lan_.*/
      options:
        type: custom:multiple-entity-row
        show_state: true
        entities:
          - attribute: ip
            name: IP
          - attribute: hostname
            name: Host
          - attribute: last_seen
            name: Last
sort:
  method: name
show_empty: false
```

B) Simple Markdown table (no extra HACS rows)

```yaml
type: markdown
title: LAN Devices
content: >
  {% set devs = expand(integration_entities('mqtt'))
                | selectattr('domain','eq','device_tracker')
                | selectattr('entity_id','search','^device_tracker\\.lan_')
                | list %}
  **Online:** {{ devs|selectattr('state','eq','home')|list|count }}

  | Name | IP | Last |
  |---|---|---|
  {% for e in devs|sort(attribute='name') %}
  | {{ e.name }} | `{{ state_attr(e.entity_id,'ip') or '' }}` | {{ state_attr(e.entity_id,'last_seen') or '' }} |
  {% endfor %}
```

### 5) “New device appeared” notification (optional)

```yaml
automation:
  - alias: "LanWatch – New device online"
    mode: single
    trigger:
      - platform: event
        event_type: state_changed
    condition: >
      {{ trigger.event.data.entity_id is string and
         trigger.event.data.entity_id.startswith('device_tracker.lan_') and
         trigger.event.data.old_state and
         trigger.event.data.old_state.state != 'home' and
         trigger.event.data.new_state and
         trigger.event.data.new_state.state == 'home' }}
    action:
      - service: persistent_notification.create
        data:
          title: "New device online"
          message: >
            {{ trigger.event.data.new_state.name }} at
            {{ state_attr(trigger.event.data.entity_id,'ip') }}
```

(Or send to mobile via `notify.mobile_app_*`.)

### Notes & tweaks
- **Multiple VLANs**: Put all subnets in `SUBNETS`, e.g. `"192.168.1.0/24,192.168.2.0/24"`. If they’re isolated, consider pulling ARP tables via your router’s API and merging.
- **Names better than reverse DNS?** You can enrich by reading DHCP leases from your router (AsusRouter integration / API) and merge by MAC.
- **Performance**: `INTERVAL_SEC` 60–120s is a sweet spot. `ABSENT_AFTER_SEC` 300 avoids flapping on Wi‑Fi clients.
- **Security**: Uses ARP ping only (no port scans). If you also want open-port snapshots occasionally, run a separate nmap hourly and publish attributes.

### Roadmap
- Optional AsusRouter hostname merge by MAC
- Vendor OUI lookup cache
- Expose `button.lanwatch_scan_now` via MQTT Discovery
- Summary sensor `sensor.lanwatch_online` 

### Build the image locally

```bash
docker build -t lanwatch:latest .
# Run it
docker run --rm --net host \
  -e MQTT_HOST=127.0.0.1 \
  -e SUBNETS="192.168.1.0/24" \
  -v $(pwd)/config/lanwatch_cache.json:/app/lanwatch_cache.json \
  lanwatch:latest
``` 

### Install as a Home Assistant custom component

- Copy `custom_components/lanwatch` into your Home Assistant `config/custom_components/` directory.
- Restart Home Assistant.
- Add the integration via Settings → Devices & Services → Add Integration → LanWatch.
- Enter your subnets, scan interval, and absent-after seconds.

The integration will create `device_tracker` entities for detected MACs and keep attributes up to date. 