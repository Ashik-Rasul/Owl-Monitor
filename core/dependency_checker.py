import sys
import os
import shutil
import importlib.util
import ctypes
from core.logger import setup_logger

logger = setup_logger(__name__)

class DependencyChecker:
    """
    Static and runtime dependency checker for Owl Monitor.
    Verifies Python version, third-party packages, system libraries, and privileges.
    """
    
    REQUIRED_MODULES = [
        ("PyYAML", "yaml"),
        ("FastAPI", "fastapi"),
        ("Uvicorn", "uvicorn"),
        ("WebSockets", "websockets"),
        ("Scapy", "scapy"),
    ]

    OPTIONAL_MODULES = [
        ("Requests", "requests"),
    ]

    @classmethod
    def check_all(cls) -> dict:
        results = {
            "python_version": f"{sys.version_split() if hasattr(sys, 'version_split') else sys.version.split()[0]}",
            "modules": {},
            "libpcap": False,
            "is_root": cls.check_root_privileges(),
            "all_required_ok": True
        }

        # Check required modules
        for display_name, module_name in cls.REQUIRED_MODULES:
            installed = importlib.util.find_spec(module_name) is not None
            version = None
            if installed:
                try:
                    mod = importlib.import_module(module_name)
                    version = getattr(mod, "__version__", "OK")
                except Exception:
                    version = "OK"
            else:
                results["all_required_ok"] = False
            results["modules"][display_name] = {"installed": installed, "version": version or "Missing"}

        # Check optional modules
        for display_name, module_name in cls.OPTIONAL_MODULES:
            installed = importlib.util.find_spec(module_name) is not None
            version = None
            if installed:
                try:
                    mod = importlib.import_module(module_name)
                    version = getattr(mod, "__version__", "OK")
                except Exception:
                    version = "OK"
            results["modules"][f"{display_name} (Optional)"] = {"installed": installed, "version": version or "Not Installed"}

        # Check libpcap availability (Linux / Unix)
        results["libpcap"] = cls.check_libpcap()

        return results

    @classmethod
    def check_root_privileges(cls) -> bool:
        """Return True if running as root/admin."""
        try:
            if hasattr(os, "geteuid"):
                return os.geteuid() == 0
            elif hasattr(ctypes, "windll"):
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass
        return False

    @classmethod
    def check_libpcap(cls) -> bool:
        """Check for libpcap / Npcap on the host system."""
        # 1. Check ctypes CDLL load
        for lib_name in ["pcap", "libpcap", "libpcap.so.1", "libpcap.so", "wpcap"]:
            try:
                ctypes.CDLL(lib_name)
                return True
            except OSError:
                continue
        # 2. Check header/library files on Linux
        pcap_paths = [
            "/usr/include/pcap.h",
            "/usr/include/pcap/pcap.h",
            "/usr/lib/x86_64-linux-gnu/libpcap.so",
            "/usr/lib64/libpcap.so"
        ]
        return any(os.path.exists(p) for p in pcap_paths)

    @classmethod
    def print_status_table(cls) -> bool:
        """Prints a clean dependency status table to the logger and returns True if required dependencies pass."""
        res = cls.check_all()
        
        lines = [
            "==================================================",
            "        OWL MONITOR DEPENDENCY CHECK              ",
            "==================================================",
            f"Python Version  : {res['python_version']} ({'OK' if sys.version_info >= (3, 8) else 'Outdated'})",
        ]

        for name, info in res["modules"].items():
            status_str = f"OK ({info['version']})" if info["installed"] else "MISSING"
            lines.append(f"{name:<16}: {status_str}")

        libpcap_status = "OK (Installed)" if res["libpcap"] else "WARNING (Missing / libpcap-dev recommended)"
        lines.append(f"{'libpcap':<16}: {libpcap_status}")

        priv_status = "Root / Administrator (Full Capabilities)" if res["is_root"] else "Non-Root User (Limited Network Capture)"
        lines.append(f"{'Privileges':<16}: {priv_status}")
        lines.append("==================================================")

        summary_msg = "\n".join(lines)
        print(summary_msg)
        logger.info("Dependency check completed.")

        if not res["is_root"]:
            logger.warning("Running without root/sudo: Packet capture and iptables actions will be disabled or simulated.")

        if not res["all_required_ok"]:
            logger.error("One or more required Python dependencies are missing. Run ./setup.sh to install.")

        return res["all_required_ok"]
