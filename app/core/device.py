"""Stable, privacy-preserving hardware fingerprinting.

The fingerprint is a salted SHA-256 over stable machine identifiers. Raw
hardware identifiers never leave this module and are never stored in the
database or returned by the API.
"""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import sys
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field

from app.config import Settings
from app.core.exceptions import DeviceIdentityError

_STRONG_COMPONENTS = {
    "machine_guid",
    "machine_id",
    "platform_uuid",
    "volume_serial",
}


@dataclass(frozen=True)
class DeviceIdentity:
    fingerprint: str
    short_id: str
    platform: str
    components: tuple[tuple[str, str], ...] = field(default=(), repr=False)

    def public_dict(self) -> dict[str, str]:
        return {
            "fingerprint": self.fingerprint,
            "short_id": self.short_id,
            "platform": self.platform,
        }


def compute_device_identity(settings: Settings) -> DeviceIdentity:
    override = (settings.device_override or "").strip()
    if override:
        if settings.environment == "production":
            raise DeviceIdentityError("Device override is disabled in production.")
        components: tuple[tuple[str, str], ...] = (("override", override),)
    else:
        components = tuple(_collect_components())

    if not components:
        raise DeviceIdentityError("No stable device identifiers are available.")

    fingerprint = fingerprint_from_components(
        components, settings.device_fingerprint_salt
    )
    return DeviceIdentity(
        fingerprint=fingerprint,
        short_id=format_short_id(fingerprint),
        platform=platform.system().lower() or sys.platform,
        components=components,
    )


def fingerprint_from_components(
    components: Iterable[tuple[str, str]], salt: str
) -> str:
    normalized = "\n".join(
        f"{name}={value}" for name, value in sorted(components) if value
    )
    if not normalized:
        raise DeviceIdentityError("No stable device identifiers are available.")
    digest = hashlib.sha256()
    digest.update(salt.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(normalized.encode("utf-8"))
    return digest.hexdigest()


def format_short_id(fingerprint: str) -> str:
    return "-".join(
        fingerprint[index : index + 4].upper() for index in range(0, 16, 4)
    )


def _collect_components() -> list[tuple[str, str]]:
    system = platform.system()
    components: list[tuple[str, str]] = [
        ("platform", system.lower() or sys.platform),
        ("architecture", platform.machine().lower()),
    ]

    if system == "Windows":
        machine_guid = _windows_machine_guid()
        if machine_guid:
            components.append(("machine_guid", machine_guid.lower()))
        volume_serial = _windows_volume_serial()
        if volume_serial:
            components.append(("volume_serial", volume_serial))
    elif system == "Linux":
        machine_id = _read_first(
            ("/etc/machine-id", "/var/lib/dbus/machine-id")
        )
        if machine_id:
            components.append(("machine_id", machine_id.lower()))
        product_uuid = _read_first(("/sys/class/dmi/id/product_uuid",))
        if product_uuid:
            components.append(("platform_uuid", product_uuid.lower()))
    elif system == "Darwin":
        platform_uuid = _darwin_platform_uuid()
        if platform_uuid:
            components.append(("platform_uuid", platform_uuid.lower()))

    if not any(name in _STRONG_COMPONENTS for name, _ in components):
        mac = _stable_mac_address()
        if mac:
            components.append(("mac_address", mac))

    return components


def _stable_mac_address() -> str | None:
    node = uuid.getnode()
    if not node:
        return None
    if (node >> 40) & 0x01:
        return None
    return f"{node:012x}"


def _windows_machine_guid() -> str | None:
    try:
        import winreg
    except ImportError:
        return None

    access_flags = (
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0),
    )
    for flags in access_flags:
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                flags,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
                if value:
                    return str(value).strip()
        except OSError:
            continue
    return None


def _windows_volume_serial() -> str | None:
    try:
        import ctypes

        drive = f"{os.environ.get('SYSTEMDRIVE', 'C:')}\\"
        serial = ctypes.c_ulong()
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive),
            None,
            0,
            ctypes.byref(serial),
            None,
            None,
            None,
            0,
        )
        if ok:
            return f"{serial.value:08x}"
    except (AttributeError, OSError, ValueError):
        return None
    return None


def _darwin_platform_uuid() -> str | None:
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in result.stdout.splitlines():
        if "IOPlatformUUID" in line and "=" in line:
            return line.split("=", 1)[1].strip().strip('"')
    return None


def _read_first(paths: Iterable[str]) -> str | None:
    for raw_path in paths:
        try:
            with open(raw_path, encoding="utf-8", errors="ignore") as handle:
                value = handle.read(256).strip()
                if value:
                    return value
        except OSError:
            continue
    return None
