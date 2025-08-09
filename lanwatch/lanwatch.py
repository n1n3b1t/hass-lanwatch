#!/usr/bin/env python3
import os, json, time, socket, hashlib
from datetime import datetime, timedelta, timezone

from netaddr import IPNetwork
from scapy.all import conf, arping   # type: ignore
import paho.mqtt.client as mqtt

# --- Env ---
MQTT_HOST   = os.getenv("MQTT_HOST","127.0.0.1")
MQTT_PORT   = int(os.getenv("MQTT_PORT","1883"))
MQTT_USER   = os.getenv("MQTT_USER") or None
MQTT_PASS   = os.getenv("MQTT_PASS") or None
SUBNETS     = [s.strip() for s in os.getenv("SUBNETS","192.168.1.0/24").split(",") if s.strip()]
INTERVAL    = int(os.getenv("INTERVAL_SEC","60"))
ABSENT_AFTER= int(os.getenv("ABSENT_AFTER_SEC","300"))
DISC_PREFIX = os.getenv("DISCOVERY_PREFIX","homeassistant").rstrip("/")
TOP_PREFIX  = os.getenv("TOPIC_PREFIX","lanwatch").rstrip("/")
NAME_PREFIX = os.getenv("NAME_PREFIX","LAN")
CACHE_FILE  = os.getenv("CACHE","/app/lanwatch_cache.json")

# --- State ---
seen = {}  # mac -> dict(ip, name, last, vendor)
now_utc = lambda: datetime.now(timezone.utc)

def load_cache():
    try:
        with open(CACHE_FILE, "r") as f:
            raw = json.load(f)
        for mac, v in raw.items():
            v["last"] = datetime.fromisoformat(v["last"])
        seen.update(raw)
    except Exception:
        pass

def save_cache():
    try:
        raw = {m:{**v, "last":v["last"].isoformat()} for m,v in seen.items()}
        with open(CACHE_FILE, "w") as f:
            json.dump(raw, f)
    except Exception:
        pass

# --- MQTT ---
client = mqtt.Client(client_id=f"lanwatch-{os.getpid()}")
if MQTT_USER: client.username_pw_set(MQTT_USER, MQTT_PASS)

def m_pub(topic, payload, retain=False, qos=1):
    client.publish(topic, payload, qos=qos, retain=retain)

def dev_uid(mac):
    return f"lan_{mac.lower().replace(':','')}"

def disc_topics(uid):
    base_cfg = f"{DISC_PREFIX}/device_tracker/lan/{uid}/config"
    state = f"{TOP_PREFIX}/devices/{uid}/state"
    attrs = f"{TOP_PREFIX}/devices/{uid}/attrs"
    cmd   = f"{TOP_PREFIX}/control/{uid}/scan"
    return base_cfg, state, attrs, cmd

def publish_discovery(mac, name_hint=""):
    uid = dev_uid(mac)
    cfg_t, state_t, attrs_t, _ = disc_topics(uid)
    payload = {
        "name": name_hint or f"{NAME_PREFIX} {mac[-5:].replace(':','')}",
        "unique_id": uid,
        "state_topic": state_t,
        "json_attributes_topic": attrs_t,
        "payload_home": "home",
        "payload_not_home": "not_home",
        "source_type": "router",
        "device": {"identifiers":[uid], "name": name_hint or f"{NAME_PREFIX} {mac}"},
    }
    m_pub(cfg_t, json.dumps(payload), retain=True)

def mark_home(mac, ip, name, vendor):
    uid = dev_uid(mac)
    _, state_t, attrs_t, _ = disc_topics(uid)
    publish_discovery(mac, name or "")
    m_pub(state_t, "home", retain=True)
    m_pub(attrs_t, json.dumps({
        "ip": ip,
        "hostname": name or "",
        "mac": mac,
        "vendor": vendor or "",
        "last_seen": now_utc().isoformat()
    }), retain=True)

def mark_away(mac):
    uid = dev_uid(mac)
    _, state_t, _, _ = disc_topics(uid)
    m_pub(state_t, "not_home", retain=True)

def rev_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def scan_once():
    hits = {}
    for net in SUBNETS:
        try:
            # expand CIDR to not choke on typos
            str(IPNetwork(net))
        except Exception:
            continue
        try:
            ans, _ = arping(net, timeout=3, verbose=0)
            for _, r in ans:
                ip = r.psrc
                mac = getattr(r, "src_mac", None)
                if not (ip and mac): 
                    continue
                if mac not in hits:
                    hits[mac] = {"ip": ip}
        except Exception as e:
            # just continue with other subnets
            continue

    # enrich + publish
    for mac, item in hits.items():
        ip = item["ip"]
        name = rev_dns(ip)
        vendor = ""  # scapy doesn't always include vendor; can add OUI db later
        prev = seen.get(mac)
        seen[mac] = {"ip": ip, "name": name, "vendor": vendor, "last": now_utc()}
        mark_home(mac, ip, name, vendor)

    # mark away
    cutoff = now_utc() - timedelta(seconds=ABSENT_AFTER)
    for mac, info in list(seen.items()):
        if info["last"] < cutoff and mac not in hits:
            mark_away(mac)
            # keep in cache but don't spam
    save_cache()

def on_connect(c, u, f, rc):
    # global scan control: lanwatch/control/scan_now
    c.subscribe(f"{TOP_PREFIX}/control/scan_now")
    c.message_callback_add(f"{TOP_PREFIX}/control/scan_now", lambda *a: scan_once())
    # per-device scan (not really used; all scan together)
    c.subscribe(f"{TOP_PREFIX}/control/+/scan")
    c.message_callback_add(f"{TOP_PREFIX}/control/+/scan", lambda *a: scan_once())

def main():
    load_cache()
    client.on_connect = on_connect
    client.connect(MQTT_HOST, MQTT_PORT, 60)
    client.loop_start()
    # initial publish for cached devices (as away)
    for mac, v in list(seen.items()):
        publish_discovery(mac, v.get("name") or "")
        mark_away(mac)
    # main loop
    while True:
        try:
            scan_once()
        except Exception:
            pass
        time.sleep(INTERVAL)

if __name__ == "__main__":
    # scapy tuning
    conf.verb = 0
    main() 