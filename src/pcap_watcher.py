# Wątek w tle skanujący katalog (zwykle /var/tmp) w poszukiwaniu nowych plików pcap
# zapisywanych przez Wireless Diagnostics → Sniffer. Plik uznajemy za gotowy, gdy jego
# mtime nie zmieniło się od `stable_seconds` — Wireless Diagnostics przestało dopisywać,
# więc można go bezpiecznie wczytać.

import glob
import os
import threading
import time
from typing import Callable

from pcap_loader import PcapLoadError, load_pcap

__all__ = ["PcapWatcher"]


class PcapWatcher:
    def __init__(
        self,
        directory: str,
        pattern: str = "airportSniff*.pcap*",
        stable_seconds: float = 3.0,
        poll_interval: float = 2.0,
    ) -> None:
        self.directory = directory
        self.pattern = pattern
        self.stable_seconds = stable_seconds
        self.poll_interval = poll_interval
        # {path: (last_mtime, processed)}
        self._seen: dict[str, tuple[float, bool]] = {}
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self.password: str = ""
        self.ssid: str = ""
        # Callbacki ustawiane przez GUI — wywoływane z wątku watcher'a (GUI musi sam
        # przekazać aktualizację na główny wątek przez root.after()).
        self.on_loaded: Callable[[str, dict[str, int]], None] | None = None
        self.on_error: Callable[[str, str], None] | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def set_credentials(self, password: str, ssid: str) -> None:
        with self._lock:
            self.password = password or ""
            self.ssid = ssid or ""

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            # Zaznacz wszystkie istniejące pliki jako już widziane — bez tego przy starcie
            # załadowałbyś każdy historyczny pcap z /var/tmp.
            self._seen = {}
            try:
                for path in glob.glob(os.path.join(self.directory, self.pattern)):
                    try:
                        self._seen[path] = (os.path.getmtime(path), True)
                    except OSError:
                        pass
            except Exception:
                pass
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._thread = None

    def _loop(self) -> None:
        while not self._stop_event.wait(self.poll_interval):
            try:
                self._poll_once()
            except Exception as e:
                if self.on_error:
                    self.on_error("(watcher)", str(e))

    def _poll_once(self) -> None:
        now = time.time()
        for path in glob.glob(os.path.join(self.directory, self.pattern)):
            try:
                mtime = os.path.getmtime(path)
                size = os.path.getsize(path)
            except OSError:
                continue
            if size == 0:
                continue

            prev = self._seen.get(path)
            if prev is None:
                self._seen[path] = (mtime, False)
                continue
            prev_mtime, processed = prev
            if processed:
                continue
            if mtime != prev_mtime:
                # plik rośnie — zaktualizuj timestamp, czekaj dalej
                self._seen[path] = (mtime, False)
                continue
            if now - mtime < self.stable_seconds:
                continue

            # plik stabilny — wczytaj
            self._seen[path] = (mtime, True)
            with self._lock:
                password = self.password
                ssid = self.ssid
            try:
                stats = load_pcap(path, password=password or None, ssid=ssid or None)
                if self.on_loaded:
                    self.on_loaded(path, stats)
            except PcapLoadError as e:
                if self.on_error:
                    self.on_error(path, str(e))
            except Exception as e:
                if self.on_error:
                    self.on_error(path, f"niespodziewany błąd: {e}")
