import importlib.util
import sys
from abc import ABC, abstractmethod
from typing import Any


class TcpInjector(ABC):
    """Base class for TCP packet injectors.

    The original project uses WinDivert through pydivert. WinDivert is a
    Windows kernel driver, so pydivert cannot work in Termux/Android where DLLs
    and the WinDivert driver are unavailable. This class keeps pydivert loading
    lazy so the application can still start in non-Windows fallback modes.
    """

    def __init__(self, w_filter: str):
        if importlib.util.find_spec("pydivert") is None:
            raise RuntimeError(
                "pydivert/WinDivert is not installed. The pydivert injector is "
                "Windows-only; use INJECTOR_BACKEND=none on Termux/Android."
            )

        pydivert = importlib.import_module("pydivert")
        self.w = pydivert.WinDivert(w_filter)

    @abstractmethod
    def inject(self, packet: Any):
        sys.exit("Not implemented")

    def run(self):
        with self.w:
            while True:
                packet = self.w.recv(65575)
                self.inject(packet)
