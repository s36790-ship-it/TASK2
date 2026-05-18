# Czyta pcap (opcjonalnie najpierw deszyfrując WPA2/WPA3 przez tshark)
# i przepuszcza każdy pakiet przez _handle() każdego snifera, dzięki czemu
# wpisuje się tym samym kodem do bazy co live capture.

import os
import shutil
import subprocess
import tempfile

from scapy.utils import rdpcap
# Rejestruje dissektor 802.11 dla pcapów z Wireless Diagnostics / tshark monitor mode.
from scapy.layers.dot11 import RadioTap, Dot11  # noqa: F401

from sniffers import arp_sniffer, dns_sniffer, ssdp_sniffer, tls_sniffer

__all__ = ["load_pcap", "PcapLoadError", "find_tshark"]


# Lokalizacje, w których tshark zwykle siedzi na macOS — Wireshark.app trzyma go w bundle,
# Homebrew kładzie w /opt/homebrew/bin lub /usr/local/bin.
_TSHARK_CANDIDATES = [
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/opt/homebrew/bin/tshark",
    "/usr/local/bin/tshark",
    "/usr/bin/tshark",
]


class PcapLoadError(Exception):
    pass


def find_tshark() -> str | None:
    found = shutil.which("tshark")
    if found:
        return found
    for path in _TSHARK_CANDIDATES:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return None


def _decrypt_with_tshark(input_pcap: str, password: str, ssid: str) -> str:
    tshark = find_tshark()
    if tshark is None:
        raise PcapLoadError(
            "tshark nie został znaleziony. Zainstaluj Wireshark "
            "(brew install --cask wireshark) lub upewnij się, że tshark jest w PATH."
        )

    fd, output_path = tempfile.mkstemp(suffix="_decrypted.pcap")
    os.close(fd)

    # tshark UAT dla kluczy 802.11: typ "wpa-pwd" i wartość "hasło:SSID".
    # Cudzysłowy są częścią formatu UAT — tshark je sam parsuje.
    uat_arg = f'uat:80211_keys:"wpa-pwd","{password}:{ssid}"'

    try:
        subprocess.run(
            [
                tshark,
                "-r", input_pcap,
                "-w", output_path,
                "-o", "wlan.enable_decryption:TRUE",
                "-o", uat_arg,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as e:
        os.unlink(output_path)
        stderr = (e.stderr or "").strip() or "(brak wyjścia stderr)"
        raise PcapLoadError(f"tshark zwrócił błąd:\n{stderr}") from e
    except subprocess.TimeoutExpired:
        os.unlink(output_path)
        raise PcapLoadError("tshark przekroczył limit czasu (120s).")

    return output_path


def load_pcap(path: str, password: str | None = None, ssid: str | None = None) -> dict[str, int]:
    """Wczytuje pcap, opcjonalnie najpierw deszyfrując WPA2/WPA3.
    Zwraca słownik {'total': N, 'arp': X, 'dns': Y, ...} z liczbą trafień per protokół.

    Jeśli password i ssid są podane, plik najpierw przechodzi przez tshark; wynikowy plik
    zawiera te same ramki z odszyfrowaną zawartością L3+, jeśli tshark zobaczył 4-way handshake."""
    if not os.path.exists(path):
        raise PcapLoadError(f"Plik nie istnieje: {path}")

    decrypted_path: str | None = None
    if password and ssid:
        decrypted_path = _decrypt_with_tshark(path, password, ssid)
        work_path = decrypted_path
    else:
        work_path = path

    try:
        packets = rdpcap(work_path)
    except Exception as e:
        if decrypted_path:
            try:
                os.unlink(decrypted_path)
            except Exception:
                pass
        raise PcapLoadError(f"Nie udało się otworzyć pcap: {e}") from e

    stats = {"total": len(packets), "errors": 0}
    for sniffer in (arp_sniffer, ssdp_sniffer, dns_sniffer, tls_sniffer):
        for pkt in packets:
            try:
                sniffer._handle(pkt)
            except Exception:
                stats["errors"] += 1

    if decrypted_path:
        try:
            os.unlink(decrypted_path)
        except Exception:
            pass

    return stats
