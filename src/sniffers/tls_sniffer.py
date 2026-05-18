# Pasywny sniffer TLS ClientHello: wyciąga SNI (nazwę hosta, do którego klient się łączy)
# i liczy fingerprint JA3 (https://github.com/salesforce/ja3) z pól ClientHello.

import hashlib
import struct
import subprocess
import sys
import threading
import time

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sniff
from scapy.utils import PcapReader
# Import rejestruje DLT 127 (IEEE802_11_RADIO) w conf.l2types — bez tego scapy nie wie,
# jak rozkodować ramki z monitor mode i traktuje je jako surowe bajty, więc IP/TCP nigdy
# nie pojawia się w packet[...], nawet dla niezaszyfrowanego ruchu.
from scapy.layers.dot11 import RadioTap, Dot11  # noqa: F401

from database import TLSEvent, SessionLocal, init_db, utcnow

__all__ = [
    "start",
    "start_in_background",
    "set_iface",
    "set_monitor_mode",
    "is_monitor_mode",
    "set_wpa_credentials",
    "set_channel",
    "get_stats",
]

_BPF = "tcp port 443"

# Stan działającego snifera trzymamy w module, żeby GUI mogło przełączać interfejs
# i tryb monitor (Wi-Fi) niezależnie, bez utraty drugiego ustawienia.
_lock = threading.Lock()
_current: "_TsharkSniffer | None" = None
_iface: str | None = None
_monitor: bool = False
# Klucze do deszyfracji on-the-fly w monitor mode. Pusty string = brak deszyfracji.
_wpa_password: str = ""
_wpa_ssid: str = ""
# Kanał Wi-Fi do zablokowania w monitor mode (przed startem tshark).
# None = używaj systemowego domyślnego.
_channel: int | None = None

# Liczniki diagnostyczne — pozwalają w GUI rozróżnić "tshark nic nie wysłał" od
# "ramki przychodzą, ale są zaszyfrowane" od "ramki dochodzą, ale to nie ClientHello".
_stats_lock = threading.Lock()
_stats = {"frames": 0, "tcp": 0, "client_hellos": 0}


def get_stats() -> dict[str, int]:
    with _stats_lock:
        return dict(_stats)


def _reset_stats() -> None:
    with _stats_lock:
        _stats["frames"] = 0
        _stats["tcp"] = 0
        _stats["client_hellos"] = 0

# Wartości GREASE (RFC 8701) — Chrome i inne klienty losowo wstrzykują je do listy
# szyfrów/rozszerzeń/krzywych. JA3 musi je pominąć, inaczej fingerprint zmienia się przy każdym
# połączeniu.
_GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
           0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


def _u16(b: bytes, i: int) -> int:
    return struct.unpack(">H", b[i:i + 2])[0]


def _parse_client_hello(data: bytes) -> tuple[str, str, str] | None:
    # Rekord TLS: content_type(1) + version(2) + length(2). 0x16 = Handshake.
    # UWAGA: jeśli ClientHello jest rozbity na kilka segmentów TCP (np. duże rozszerzenia,
    # ECH/ESNI), drugi segment trafia tu jako "dane po record header" i parser go pominie.
    # Pełna obsługa wymagałaby ponownego składania strumienia TCP — pomijamy, bo
    # w praktyce >99% ClientHello mieści się w jednym segmencie.
    if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:
        return None  # 0x01 = ClientHello w nagłówku Handshake
    try:
        pos = 9
        version = _u16(data, pos); pos += 2
        pos += 32  # random
        sid_len = data[pos]; pos += 1 + sid_len
        cs_len = _u16(data, pos); pos += 2
        ciphers = [_u16(data, pos + i) for i in range(0, cs_len, 2) if _u16(data, pos + i) not in _GREASE]
        pos += cs_len
        cm_len = data[pos]; pos += 1 + cm_len
        ext_total = _u16(data, pos); pos += 2
        end = pos + ext_total

        exts: list[int] = []
        curves: list[int] = []
        formats: list[int] = []
        sni = ""
        alpn_protos: list[str] = []

        while pos + 4 <= end:
            etype = _u16(data, pos)
            elen = _u16(data, pos + 2)
            edata = data[pos + 4:pos + 4 + elen]
            pos += 4 + elen
            if etype in _GREASE:
                continue
            exts.append(etype)
            if etype == 0x0000 and len(edata) >= 5:
                # SNI: list_len(2) + entry_type(1) + name_len(2) + name
                name_len = _u16(edata, 3)
                sni = edata[5:5 + name_len].decode("utf-8", errors="ignore")
            elif etype == 0x0010 and len(edata) >= 2:
                # ALPN: list_len(2) + entries [str_len(1) + str_bytes]. Silny sygnał klasy
                # urządzenia — przeglądarki zwykle proponują "h2"+"http/1.1", aplikacje
                # mobilne często tylko jedną wartość.
                list_len = _u16(edata, 0)
                i = 2
                while i < 2 + list_len and i < len(edata):
                    s_len = edata[i]
                    alpn_protos.append(edata[i + 1:i + 1 + s_len].decode("ascii", errors="ignore"))
                    i += 1 + s_len
            elif etype == 0x000a and len(edata) >= 2:
                # supported_groups (krzywe eliptyczne): list_len(2) + uint16[]
                gl = _u16(edata, 0)
                for i in range(0, gl, 2):
                    g = _u16(edata, 2 + i)
                    if g not in _GREASE:
                        curves.append(g)
            elif etype == 0x000b and len(edata) >= 1:
                # ec_point_formats: list_len(1) + uint8[]
                fl = edata[0]
                formats.extend(edata[1:1 + fl])

        ja3_str = "{},{},{},{},{}".format(
            version,
            "-".join(str(c) for c in ciphers),
            "-".join(str(e) for e in exts),
            "-".join(str(c) for c in curves),
            "-".join(str(f) for f in formats),
        )
        alpn = ",".join(alpn_protos)
        return sni, alpn, hashlib.md5(ja3_str.encode()).hexdigest()
    except (struct.error, IndexError):
        return None


def _upsert(ip: str, sni: str, alpn: str, ja3: str) -> None:
    with SessionLocal() as session:
        session.add(TLSEvent(ip=ip, sni=sni, alpn=alpn, ja3=ja3, timestamp=utcnow()))
        session.commit()


def _handle(packet) -> None:
    with _stats_lock:
        _stats["frames"] += 1
        if TCP in packet:
            _stats["tcp"] += 1
    if TCP not in packet or Raw not in packet:
        return
    result = _parse_client_hello(bytes(packet[Raw].load))
    if result is None:
        return
    sni, alpn, ja3 = result
    with _stats_lock:
        _stats["client_hellos"] += 1
    src_ip = packet[IP].src if IP in packet else ""
    _upsert(src_ip, sni, alpn, ja3)


def start(iface: str | None = None) -> None:
    # Filtr BPF zawęża do TCP/443 — parser i tak odrzuca pakiety, które nie są ClientHello.
    sniff(filter=_BPF, prn=_handle, store=False, iface=iface)


def _default_iface() -> str | None:
    # tshark nie domyśla się portu sam — bez jawnego iface bierze pierwszy z listy,
    # co bywa lo0 albo bridge0. Ustalamy port Wi-Fi z góry.
    if sys.platform == "darwin":
        return "en0"
    if sys.platform.startswith("linux"):
        return "wlan0"
    return None


class _TsharkSniffer:
    """Live capture przez tshark zamiast scapy.AsyncSniffer. tshark pisze ramki w formacie pcap
    na stdout, scapy.PcapReader parsuje strumień, każdy pakiet trafia do _handle()."""

    def __init__(self, iface: str | None, monitor: bool, wpa_password: str = "", wpa_ssid: str = "", channel: int | None = None) -> None:
        self.iface = iface
        self.monitor = monitor
        self.wpa_password = wpa_password
        self.wpa_ssid = wpa_ssid
        self.channel = channel
        self.proc: subprocess.Popen | None = None
        self.thread: threading.Thread | None = None
        self.stderr_thread: threading.Thread | None = None
        self.running = False
        self.exception: BaseException | None = None
        self.stderr_tail: list[str] = []

    def start(self) -> None:
        from pcap_loader import find_tshark  # lazy: pcap_loader importuje ten moduł
        _reset_stats()
        if self.monitor and self.channel and self.iface:
            self._try_set_channel()
        tshark = find_tshark()
        if tshark is None:
            raise RuntimeError(
                "tshark nie znaleziony. Zainstaluj Wireshark (brew install --cask wireshark)."
            )

        cmd = [tshark, "-w", "-", "-l"]
        # -i przekazujemy tylko, jeśli mamy konkretną nazwę. tshark z brakującym -i bierze
        # domyślny port wg swojej listy (zwykle Wi-Fi), tshark z "-i ''" zwraca błąd.
        if self.iface:
            cmd.extend(["-i", self.iface])
        if self.monitor:
            # -I = monitor mode (rfmon). Filtr BPF tutaj nie zadziała na ramkach 802.11,
            # więc go nie przekazujemy — _handle i tak odrzuca to, co nie jest ClientHello.
            cmd.append("-I")
            # On-the-fly deszyfracja WPA2/WPA3 Personal. tshark potrzebuje 4-way handshake
            # zachowanego w buforze ringbuffera — jeśli klient był już połączony przed startem,
            # trzeba go zmusić do reconnect, żeby zobaczyć ramki EAPOL.
            if self.wpa_password and self.wpa_ssid:
                uat_arg = f'uat:80211_keys:"wpa-pwd","{self.wpa_password}:{self.wpa_ssid}"'
                cmd.extend(["-o", "wlan.enable_decryption:TRUE", "-o", uat_arg])
        else:
            cmd.extend(["-f", _BPF])

        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.running = True
        self.thread = threading.Thread(target=self._read_loop, daemon=True)
        self.thread.start()
        self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self.stderr_thread.start()

    def _read_loop(self) -> None:
        try:
            assert self.proc is not None and self.proc.stdout is not None
            reader = PcapReader(self.proc.stdout)
            for pkt in reader:
                try:
                    _handle(pkt)
                except Exception:
                    # nie wywalaj wątku z powodu pojedynczego źle sparsowanego pakietu
                    pass
        except Exception as exc:
            self.exception = exc
        finally:
            self.running = False

    def _read_stderr(self) -> None:
        try:
            assert self.proc is not None and self.proc.stderr is not None
            for raw in self.proc.stderr:
                line = raw.decode("utf-8", errors="ignore").rstrip()
                if not line:
                    continue
                self.stderr_tail.append(line)
                if len(self.stderr_tail) > 40:
                    self.stderr_tail.pop(0)
        except Exception:
            pass

    def _try_set_channel(self) -> None:
        # Zablokowanie radia na konkretnym kanale przed monitor mode capture.
        # Linux: iw dev <iface> set channel N — wymaga roota i pakietu `iw`.
        # macOS 14.4+: airport CLI usunięte, CoreWLAN wymaga entitlements — niemożliwe.
        # Windows: brak standardowego CLI; pomijamy.
        if sys.platform.startswith("linux"):
            try:
                result = subprocess.run(
                    ["iw", "dev", self.iface or "", "set", "channel", str(self.channel)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode != 0:
                    err = (result.stderr or result.stdout or "").strip() or "unknown"
                    self.stderr_tail.append(f"[channel] iw zwróciło błąd: {err}")
            except FileNotFoundError:
                self.stderr_tail.append("[channel] brak narzędzia 'iw' — zainstaluj pakiet iw")
            except Exception as e:
                self.stderr_tail.append(f"[channel] iw exception: {e}")
        elif sys.platform == "darwin":
            self.stderr_tail.append(
                f"[channel] kanał {self.channel} zignorowany — macOS 14.4+ usunęło 'airport' CLI; "
                "użyj Wireless Diagnostics → Sniffer, żeby ustawić kanał, albo przejdź na pcap loader."
            )
        else:
            self.stderr_tail.append(f"[channel] ustawianie kanału nie wspierane na {sys.platform}")

    def stop(self) -> None:
        if self.proc is not None:
            try:
                self.proc.terminate()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.running = False
        if self.thread is not None:
            self.thread.join(timeout=2)
        if self.stderr_thread is not None:
            self.stderr_thread.join(timeout=1)


def _spawn(iface: str | None, monitor: bool) -> _TsharkSniffer:
    # Zawsze preferuj wybrany przez użytkownika iface; jak go nie ma, dla każdego trybu
    # bierz sensowny domyślny port Wi-Fi (en0/wlan0). To zapobiega temu, że tshark
    # po wyłączeniu monitor mode bierze coś przypadkowego.
    effective = iface or _default_iface()
    sniffer = _TsharkSniffer(effective, monitor, _wpa_password, _wpa_ssid, _channel)
    sniffer.start()
    # tshark sygnalizuje błędy (zły iface, brak uprawnień, brak monitor mode) przez stderr
    # i kończy się natychmiast. Czekamy chwilę i sprawdzamy, czy wciąż żyje.
    time.sleep(0.3)
    if sniffer.proc is None or sniffer.proc.poll() is not None:
        tail = "\n".join(sniffer.stderr_tail[-10:]) or "(brak wyjścia stderr z tshark)"
        try:
            sniffer.stop()
        except Exception:
            pass
        raise RuntimeError(
            f"tshark zakończył się od razu (iface={effective!r} monitor={monitor}).\n"
            f"Ostatnie linie stderr:\n{tail}"
        )
    return sniffer


def start_in_background(iface: str | None = None) -> None:
    global _current, _iface
    with _lock:
        if _current is not None:
            return
        _current = _spawn(iface, _monitor)
        _iface = iface


def set_iface(iface: str | None) -> None:
    global _current, _iface
    with _lock:
        if _current is not None:
            try:
                _current.stop()
            except Exception:
                pass
        _current = _spawn(iface, _monitor)
        _iface = iface


def set_monitor_mode(monitor: bool) -> None:
    """Zatrzymuje sniffer i startuje go ponownie z innym ustawieniem monitor mode.
    Zachowuje aktualnie wybrany interfejs."""
    global _current, _monitor
    with _lock:
        if _current is not None:
            try:
                _current.stop()
            except Exception:
                pass
        _current = _spawn(_iface, monitor)
        _monitor = monitor


def is_monitor_mode() -> bool:
    return _monitor


def set_wpa_credentials(password: str | None, ssid: str | None) -> None:
    """Zapamiętuje hasło + SSID do deszyfracji on-the-fly w monitor mode.
    Zmiany działają od następnego restartu snifera (toggle monitor mode lub set_iface)."""
    global _wpa_password, _wpa_ssid
    _wpa_password = password or ""
    _wpa_ssid = ssid or ""


def set_channel(channel: int | None) -> None:
    """Zapamiętuje kanał Wi-Fi do zablokowania przed startem tshark w monitor mode.
    Zmiana wejdzie w życie po kolejnym restarcie snifera (toggle monitor mode)."""
    global _channel
    _channel = channel if channel else None


if __name__ == "__main__":
    # Tryb samodzielny do testów. Wymaga uprawnień root/admin (surowe gniazda).
    init_db()
    start()
