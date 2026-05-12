"""Embedded oBIX HTTP server that publishes discovered bus devices.

Niagara AX and N4 stations with an oBIX client connector can point at
http://<pc-ip>:<port>/obix/ to pull discovered devices into the station
component tree automatically — no NDK or Fox protocol required.

In Workbench: Drivers → Add Driver → oBIX Client → set Root URL to
http://<this-pc-ip>:<port>/obix/
"""
from __future__ import annotations

import socketserver
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import xml.etree.ElementTree as ET


class _DeviceRecord:
    __slots__ = ("address", "protocol", "first_seen", "last_seen", "packet_count")

    def __init__(self, address: str, protocol: str) -> None:
        now = datetime.now(timezone.utc)
        self.address = address
        self.protocol = protocol
        self.first_seen = now
        self.last_seen = now
        self.packet_count = 1

    def touch(self, protocol: str) -> None:
        self.last_seen = datetime.now(timezone.utc)
        self.protocol = protocol
        self.packet_count += 1


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sort_key(addr: str) -> tuple:
    try:
        return (0, int(addr))
    except ValueError:
        return (1, addr)


def _sub(parent: ET.Element, tag: str, **attrs: str) -> ET.Element:
    e = ET.SubElement(parent, tag)
    for k, v in attrs.items():
        e.set(k, v)
    return e


def _device_elem(dev: _DeviceRecord) -> ET.Element:
    elem = ET.Element("obj")
    elem.set("name", f"Device_{dev.address}")
    elem.set("href", f"/obix/BusSniffer/Device_{dev.address}/")
    elem.set("displayName", f"Device {dev.address} ({dev.protocol})")
    _sub(elem, "int",     name="address",     val=dev.address if dev.address.isdigit() else "0", displayName="Address")
    _sub(elem, "str",     name="protocol",    val=dev.protocol,            displayName="Protocol")
    _sub(elem, "abstime", name="firstSeen",   val=_iso(dev.first_seen),    displayName="First Seen")
    _sub(elem, "abstime", name="lastSeen",    val=_iso(dev.last_seen),     displayName="Last Seen")
    _sub(elem, "int",     name="packetCount", val=str(dev.packet_count),   displayName="Packet Count")
    return elem


def _xml_doc(root: ET.Element) -> str:
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A002
        pass  # suppress access log noise

    def do_GET(self) -> None:
        path = self.path.split("?")[0].rstrip("/") or "/obix"
        bridge: ObixBridgeServer = self.server.bridge  # type: ignore[attr-defined]

        if path in ("/obix", "/obix/about"):
            body = bridge._about_xml()
        elif path == "/obix/BusSniffer":
            body = bridge._list_xml()
        elif path.startswith("/obix/BusSniffer/Device_"):
            addr = path[len("/obix/BusSniffer/Device_"):].rstrip("/")
            body = bridge._device_xml(addr)
        else:
            self.send_response(404)
            self.end_headers()
            return

        if body is None:
            self.send_response(404)
            self.end_headers()
            return

        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class _Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    bridge: "ObixBridgeServer"


class ObixBridgeServer:
    """Thread-safe oBIX device registry with an embedded HTTP server.

    Call ``update_device`` from any thread as devices are discovered.
    Call ``start`` / ``stop`` to control the server lifecycle.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._devices: dict[str, _DeviceRecord] = {}
        self._http: _Server | None = None
        self._thread: threading.Thread | None = None

    # ── device registry ───────────────────────────────────────────────

    def update_device(self, address: str, protocol: str) -> None:
        """Record a device observation. Thread-safe; called from sniff thread."""
        with self._lock:
            if address in self._devices:
                self._devices[address].touch(protocol)
            else:
                self._devices[address] = _DeviceRecord(address, protocol)

    def clear(self) -> None:
        """Remove all device records."""
        with self._lock:
            self._devices.clear()

    # ── server lifecycle ──────────────────────────────────────────────

    def start(self, port: int) -> tuple[bool, str]:
        """Start serving on *port*. Returns (success, status_message)."""
        if self._http is not None:
            return False, "Already running"
        try:
            srv = _Server(("", port), _Handler)
            srv.bridge = self
            self._http = srv
            self._thread = threading.Thread(target=srv.serve_forever, daemon=True)
            self._thread.start()
            return True, f"Running on :{port}"
        except OSError as exc:
            self._http = None
            return False, f"Failed: {exc}"

    def stop(self) -> None:
        if self._http:
            self._http.shutdown()
            self._http = None
        self._thread = None

    @property
    def running(self) -> bool:
        return self._http is not None

    # ── XML builders (called from HTTP handler thread) ─────────────────

    def _about_xml(self) -> str:
        root = ET.Element("obj")
        root.set("is", "obix:About")
        root.set("href", "/obix/")
        _sub(root, "str", name="serverName", val="Bus Sniffer",                        displayName="Server Name")
        _sub(root, "str", name="serverTime", val=_iso(datetime.now(timezone.utc)),     displayName="Server Time")
        _sub(root, "str", name="vendorName", val="Field Tools",                        displayName="Vendor")
        _sub(root, "ref", name="BusSniffer", href="/obix/BusSniffer/",                 displayName="Bus Sniffer Devices")
        return _xml_doc(root)

    def _list_xml(self) -> str:
        root = ET.Element("obj")
        root.set("name", "BusSniffer")
        root.set("href", "/obix/BusSniffer/")
        root.set("displayName", "Bus Sniffer Devices")
        with self._lock:
            devices = list(self._devices.values())
        for dev in sorted(devices, key=lambda d: _sort_key(d.address)):
            root.append(_device_elem(dev))
        return _xml_doc(root)

    def _device_xml(self, addr: str) -> str | None:
        with self._lock:
            dev = self._devices.get(addr)
        if dev is None:
            return None
        return _xml_doc(_device_elem(dev))
