import ctypes
from ctypes import wintypes
import json
import os
import queue
import shutil
import subprocess
import threading
import tkinter as tk
import uuid
from tkinter import filedialog, messagebox, scrolledtext, ttk

from recovery_engine import SIGNATURES, recover


class SafetyError(ValueError):
    pass


_INVENTORY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$allPartitions = @(Get-Partition)
$disks = @(Get-Disk | ForEach-Object {
    $disk = $_
    $partitions = @($allPartitions | Where-Object DiskNumber -EQ $disk.Number | ForEach-Object {
        [pscustomobject]@{
            number = $_.PartitionNumber
            drive_letter = $_.DriveLetter
            size = $_.Size
            type = [string]$_.Type
        }
    })
    [pscustomobject]@{
        number = $disk.Number
        name = $disk.FriendlyName
        unique_id = $disk.UniqueId
        bus_type = [string]$disk.BusType
        size = $disk.Size
        partitions = $partitions
    }
})
ConvertTo-Json -InputObject $disks -Depth 5 -Compress
"""

_SUPPORTED_BUS_TYPES = {"ATA", "SATA", "SAS", "NVMe", "USB", "SD", "MMC"}
DISCONNECTED = "disconnected"


def list_disks():
    if os.name != "nt":
        raise SafetyError("Disk inventory and safety checks require Windows.")
    executable = shutil.which("powershell.exe")
    if not executable:
        raise SafetyError("Windows PowerShell was not found; disk safety cannot be verified.")
    try:
        result = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", _INVENTORY_SCRIPT],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SafetyError(f"Could not read Windows disk inventory: {exc}") from exc
    if result.returncode:
        raise SafetyError(f"Could not read Windows disk inventory: {result.stderr.strip()}")
    try:
        disks = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SafetyError("Windows disk inventory returned invalid data.") from exc
    if not isinstance(disks, list) or not all(isinstance(disk, dict) for disk in disks):
        raise SafetyError("Windows disk inventory returned an unexpected result.")
    return disks


def volume_disks(path):
    """Return Windows disk numbers for the existing path's resolved volume."""
    if os.name != "nt":
        raise SafetyError("Volume safety checks require Windows.")
    resolved = os.path.realpath(path, strict=True)
    if resolved.startswith("\\\\") and not resolved.startswith("\\\\?\\"):
        raise SafetyError("Network paths cannot be verified as separate physical disks.")

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel.GetVolumePathNameW.restype = wintypes.BOOL
    kernel.GetVolumeNameForVolumeMountPointW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD
    ]
    kernel.GetVolumeNameForVolumeMountPointW.restype = wintypes.BOOL
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.DeviceIoControl.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    kernel.DeviceIoControl.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    mount = ctypes.create_unicode_buffer(32768)
    volume = ctypes.create_unicode_buffer(32768)
    if not kernel.GetVolumePathNameW(resolved, mount, len(mount)):
        raise SafetyError(f"Cannot identify the volume for {path}: {ctypes.WinError(ctypes.get_last_error())}")
    if not kernel.GetVolumeNameForVolumeMountPointW(mount.value, volume, len(volume)):
        raise SafetyError(f"Cannot identify a local volume for {path}: {ctypes.WinError(ctypes.get_last_error())}")

    handle = kernel.CreateFileW(volume.value.rstrip("\\"), 0, 7, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        raise SafetyError(f"Cannot inspect volume for {path}: {ctypes.WinError(ctypes.get_last_error())}")

    class DiskExtent(ctypes.Structure):
        _fields_ = [
            ("disk_number", wintypes.DWORD),
            ("starting_offset", ctypes.c_longlong),
            ("extent_length", ctypes.c_longlong),
        ]

    class VolumeExtents(ctypes.Structure):
        _fields_ = [("count", wintypes.DWORD), ("extents", DiskExtent * 1)]

    buffer = ctypes.create_string_buffer(65536)
    returned = wintypes.DWORD()
    try:
        if not kernel.DeviceIoControl(
            handle, 0x00560000, None, 0, buffer, len(buffer), ctypes.byref(returned), None
        ):
            raise SafetyError(f"Cannot map volume for {path}: {ctypes.WinError(ctypes.get_last_error())}")
    finally:
        kernel.CloseHandle(handle)
    offset = VolumeExtents.extents.offset
    if returned.value < offset:
        raise SafetyError(f"Incomplete volume mapping for {path}.")
    count = wintypes.DWORD.from_buffer_copy(buffer).value
    if not count or offset + count * ctypes.sizeof(DiskExtent) > returned.value:
        raise SafetyError(f"Incomplete volume mapping for {path}.")
    return {
        DiskExtent.from_buffer_copy(buffer, offset + i * ctypes.sizeof(DiskExtent)).disk_number
        for i in range(count)
    }


def validate_destination(image_path, output_dir, original_source):
    """Reject output on the image host or the user-identified original source disk."""
    if original_source is None:
        raise SafetyError("Identify the original disk or confirm it is disconnected.")
    try:
        image_disks = volume_disks(image_path)
        output_disks = volume_disks(output_dir)
    except OSError as exc:
        raise SafetyError(f"Cannot resolve recovery paths: {exc}") from exc
    inventory = list_disks()
    disks = {disk.get("number"): disk for disk in inventory}
    for number in image_disks | output_disks:
        disk = disks.get(number)
        if not disk or disk.get("bus_type") not in _SUPPORTED_BUS_TYPES:
            raise SafetyError(
                f"Disk {number} has an unknown or virtual storage topology; "
                "safe separation cannot be verified."
            )
    if image_disks & output_disks:
        raise SafetyError("The output and image are on the same physical disk.")
    if original_source != DISCONNECTED:
        if not isinstance(original_source, tuple) or len(original_source) != 2:
            raise SafetyError("Select a valid original source disk.")
        number, unique_id = original_source
        disk = disks.get(number)
        if not unique_id or not disk or disk.get("unique_id") != unique_id:
            raise SafetyError("The selected original disk changed or is no longer present. Refresh the disk list.")
        if disk.get("bus_type") not in _SUPPORTED_BUS_TYPES:
            raise SafetyError(
                "The original disk has an unknown or virtual storage topology; "
                "safe separation cannot be verified."
            )
        if number in output_disks:
            raise SafetyError("The output is on the original source disk.")


class OriginalDiskSelector(ttk.LabelFrame):
    def __init__(self, parent):
        super().__init__(parent, text="Original source disk")
        self.choice = tk.StringVar()
        self.options = {}
        self.combo = ttk.Combobox(self, textvariable=self.choice, state="readonly", width=55)
        self.combo.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        ttk.Button(self, text="List disks / refresh", command=self.refresh).pack(side="left", padx=5)

    def refresh(self):
        try:
            disks = list_disks()
        except SafetyError as exc:
            self.options = {}
            self.combo["values"] = ()
            self.choice.set("")
            messagebox.showerror("Disk inventory", str(exc), parent=self)
            return
        self.options = {"Original disk is disconnected": DISCONNECTED}
        for disk in disks:
            number = disk.get("number")
            unique_id = disk.get("unique_id")
            if not isinstance(number, int):
                continue
            partition_details = ", ".join(
                f"{p.get('drive_letter') or '-'}: partition {p.get('number')} ({p.get('type')})"
                for p in disk.get("partitions", [])
            ) or "no partitions listed"
            label = (
                f"Disk {number}: {disk.get('name')} ({disk.get('bus_type')}, "
                f"{disk.get('size')} bytes) | {partition_details}"
                f"{'' if unique_id else ' | no stable ID; cannot select'}"
            )
            self.options[label] = (number, unique_id)
        self.combo["values"] = tuple(self.options)
        self.choice.set("")

    def selected_source(self):
        if self.choice.get() not in self.options:
            raise SafetyError("List disks and select the original source disk, or confirm it is disconnected.")
        return self.options[self.choice.get()]


def open_smart_window(root):
    window = tk.Toplevel(root)
    window.title("SMART diagnostics")
    window.geometry("760x500")
    device = tk.StringVar()
    status = tk.StringVar(value="Enter a smartctl device identifier.")
    results = queue.Queue()

    tk.Label(
        window,
        text="Requires smartctl on PATH and appropriate permissions. "
             "Checking SMART may wake the drive.",
        wraplength=730,
    ).pack(padx=10, pady=5)
    tk.Label(window, text="smartctl device identifier").pack(anchor="w", padx=10)
    tk.Entry(window, textvariable=device, width=70).pack(fill="x", padx=10)

    output = scrolledtext.ScrolledText(window, wrap="word", state="disabled")
    output.pack(fill="both", expand=True, padx=10, pady=5)
    tk.Label(window, textvariable=status).pack(pady=5)

    def worker(device_name):
        try:
            result = subprocess.run(
                ["smartctl", "--all", device_name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                timeout=30,
                check=False,
            )
            results.put(("done", result.returncode, result.stdout, result.stderr))
        except FileNotFoundError:
            results.put(("error", "smartctl was not found. Install smartmontools and add it to PATH."))
        except subprocess.TimeoutExpired:
            results.put(("error", "smartctl timed out after 30 seconds."))
        except OSError as exc:
            results.put(("error", f"Could not run smartctl: {exc}"))

    def poll():
        try:
            result = results.get_nowait()
        except queue.Empty:
            window.after(150, poll)
            return

        check_button.config(state="normal")
        if result[0] == "error":
            status.set("SMART check failed.")
            messagebox.showerror("SMART diagnostics", result[1], parent=window)
            return

        _, returncode, stdout, stderr = result
        output.config(state="normal")
        output.delete("1.0", "end")
        output.insert("end", stdout)
        if stderr:
            output.insert("end", "\nStandard error:\n" + stderr)
        output.config(state="disabled")
        status.set(f"smartctl exit code: {returncode} (see output for health and errors).")

    def start_check():
        device_name = device.get().strip()
        if not device_name or device_name.startswith("-"):
            messagebox.showerror(
                "SMART diagnostics", "Enter a valid smartctl device identifier.", parent=window
            )
            return
        check_button.config(state="disabled")
        status.set("Checking SMART data...")
        threading.Thread(target=worker, args=(device_name,), daemon=True).start()
        window.after(150, poll)

    check_button = tk.Button(window, text="Check SMART", command=start_check)
    check_button.pack(pady=5)


def open_filesystem_window(root, active_jobs):
    window = tk.Toplevel(root)
    window.title("Filesystem recovery from image")
    window.geometry("760x360")
    source = tk.StringVar()
    destination = tk.StringVar()
    offset = tk.StringVar()
    include_allocated = tk.BooleanVar(value=False)
    status = tk.StringVar(value="Select an image and a destination on another drive.")
    results = queue.Queue()
    cancel_event = threading.Event()
    job = object()

    def select_source():
        path = filedialog.askopenfilename(parent=window, title="Select disk or partition image")
        if path:
            source.set(path)

    def select_destination():
        path = filedialog.askdirectory(parent=window, title="Select output folder")
        if path:
            destination.set(path)

    def worker(executable, image_path, run_dir, sector_offset, recover_all):
        log_path = os.path.join(run_dir, "tsk_recover.log")
        output_path = os.path.join(run_dir, "files")
        command = [executable]
        if recover_all:
            command.append("-e")
        if sector_offset:
            command.extend(["-o", sector_offset])
        command.extend([image_path, output_path])

        try:
            os.mkdir(output_path)
            with open(log_path, "x", encoding="utf-8") as log:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT
                )
                while True:
                    try:
                        returncode = process.wait(timeout=0.25)
                        break
                    except subprocess.TimeoutExpired:
                        if cancel_event.is_set():
                            process.terminate()
                            returncode = process.wait()
                            results.put(("cancelled", run_dir, log_path, returncode))
                            return
            results.put(("done", run_dir, log_path, returncode))
        except OSError as exc:
            results.put(("error", run_dir, str(exc)))

    def poll():
        try:
            result = results.get_nowait()
        except queue.Empty:
            window.after(150, poll)
            return

        active_jobs.discard(job)
        start_button.config(state="normal")
        cancel_button.config(state="disabled")
        kind, run_dir, detail, *rest = result
        if kind == "error":
            status.set("Recovery failed.")
            messagebox.showerror(
                "Filesystem recovery", f"{detail}\nOutput folder: {run_dir}", parent=window
            )
        elif kind == "cancelled":
            status.set("Recovery cancelled; output may be incomplete.")
            messagebox.showinfo(
                "Filesystem recovery", f"Cancelled. Review the log:\n{detail}", parent=window
            )
        else:
            returncode = rest[0]
            status.set(f"Tool exited with code {returncode}; review the log.")
            show = messagebox.showinfo if returncode == 0 else messagebox.showerror
            show(
                "Filesystem recovery",
                f"Tool exit code: {returncode}\nOutput: {run_dir}\nLog: {detail}",
                parent=window,
            )

    def start():
        image_path = os.path.abspath(source.get()) if source.get() else ""
        output_dir = os.path.abspath(destination.get()) if destination.get() else ""
        sector_offset = offset.get().strip()
        if not os.path.isfile(image_path) or not os.path.isdir(output_dir):
            messagebox.showerror(
                "Filesystem recovery", "Select an image file and an output folder.", parent=window
            )
            return
        try:
            original_source = disk_selector.selected_source()
            validate_destination(image_path, output_dir, original_source)
        except SafetyError as exc:
            messagebox.showerror("Recovery safety", str(exc), parent=window)
            return
        if sector_offset and (not sector_offset.isascii() or not sector_offset.isdecimal()):
            messagebox.showerror(
                "Filesystem recovery", "The sector offset must be a non-negative integer.",
                parent=window,
            )
            return
        executable = shutil.which("tsk_recover")
        if not executable:
            messagebox.showerror(
                "Filesystem recovery",
                "tsk_recover was not found. Install The Sleuth Kit and add it to PATH.",
                parent=window,
            )
            return
        run_dir = os.path.join(output_dir, f"filesystem_recovery_{uuid.uuid4().hex}")
        try:
            os.mkdir(run_dir)
        except OSError as exc:
            messagebox.showerror("Filesystem recovery", str(exc), parent=window)
            return
        cancel_event.clear()
        active_jobs.add(job)
        start_button.config(state="disabled")
        cancel_button.config(state="normal")
        status.set("Recovery in progress. Output is written to a new folder.")
        threading.Thread(
            target=worker,
            args=(executable, image_path, run_dir, sector_offset, include_allocated.get()),
            daemon=True,
        ).start()
        window.after(150, poll)

    def close_window():
        if job in active_jobs:
            messagebox.showwarning(
                "Recovery running", "Cancel recovery and wait for it to stop.", parent=window
            )
        else:
            window.destroy()

    tk.Label(
        window, text="Requires The Sleuth Kit (tsk_recover) on PATH. Image files only."
    ).pack(pady=5)
    disk_selector = OriginalDiskSelector(window)
    disk_selector.pack(fill="x", padx=10)
    tk.Label(
        window,
        text="Identify the original disk yourself. Hardware RAID and bridges may hide shared disks.",
        wraplength=730,
    ).pack()
    source_row = tk.Frame(window)
    source_row.pack(fill="x", padx=10)
    tk.Label(source_row, text="Image").pack(side="left")
    tk.Entry(source_row, textvariable=source).pack(side="left", fill="x", expand=True, padx=5)
    tk.Button(source_row, text="Browse", command=select_source).pack(side="left")
    output_row = tk.Frame(window)
    output_row.pack(fill="x", padx=10)
    tk.Label(output_row, text="Output").pack(side="left")
    tk.Entry(output_row, textvariable=destination).pack(side="left", fill="x", expand=True, padx=5)
    tk.Button(output_row, text="Browse", command=select_destination).pack(side="left")
    offset_row = tk.Frame(window)
    offset_row.pack(fill="x", padx=10, pady=5)
    tk.Label(offset_row, text="Volume sector offset (optional)").pack(side="left")
    tk.Entry(offset_row, textvariable=offset, width=20).pack(side="left", padx=5)
    tk.Checkbutton(
        window, text="Include allocated files (default: deleted files only)",
        variable=include_allocated,
    ).pack()
    buttons = tk.Frame(window)
    buttons.pack(pady=5)
    start_button = tk.Button(buttons, text="Recover", command=start)
    start_button.pack(side="left", padx=5)
    cancel_button = tk.Button(
        buttons, text="Cancel", command=cancel_event.set, state="disabled"
    )
    cancel_button.pack(side="left", padx=5)
    tk.Label(window, textvariable=status, wraplength=680).pack()
    window.protocol("WM_DELETE_WINDOW", close_window)


def main():
    root = tk.Tk()
    root.title("Open Recovery - Image Carver")
    root.geometry("900x650")

    image_path = tk.StringVar()
    output_dir = tk.StringVar()
    status = tk.StringVar(value="Select a disk image and output folder.")
    stats_var = tk.StringVar(value="Recovered: 0 | Partial: 0 | Bad Sectors: 0")
    sector_aligned = tk.BooleanVar(value=True)
    file_types = {ext: tk.BooleanVar(value=True) for _, ext in SIGNATURES}

    msg_queue = queue.Queue()
    cancel_event = threading.Event()
    active_jobs = set()

    def select_image():
        path = filedialog.askopenfilename(
            title="Select disk image",
            filetypes=[("Disk Images", "*.img *.dd *.raw *.iso *.bin"), ("All Files", "*.*")],
        )
        if path:
            image_path.set(path)

    def select_output():
        path = filedialog.askdirectory(title="Select output folder")
        if path:
            output_dir.set(path)

    def worker(source, destination, selected_types, aligned, original_source):
        try:
            res = recover(
                source, destination, msg_queue, cancel_event,
                selected_types, aligned, original_source,
                safety_check=validate_destination,
            )
            msg_queue.put(("done", res))
        except (OSError, ValueError) as exc:
            msg_queue.put(("error", str(exc)))

    def poll_queue():
        try:
            while True:
                msg = msg_queue.get_nowait()
                kind = msg[0]

                if kind == "progress":
                    _, current, total, rec, part, bad = msg
                    pct = (current / total * 100) if total else 0
                    progress_bar["value"] = pct
                    mb_done = current / (1024 * 1024)
                    mb_total = total / (1024 * 1024)
                    status.set(f"Scanning: {mb_done:.1f} MB / {mb_total:.1f} MB ({pct:.1f}%)")
                    stats_var.set(f"Recovered: {rec} | Partial: {part} | Bad Sectors: {bad}")

                elif kind == "file":
                    offset, ext, result_status, size, errors, path = msg[1]
                    results_tree.insert(
                        "", "end", values=(offset, ext, result_status, size, errors, path)
                    )

                elif kind == "done":
                    rec, part, bad, cancelled, report_path = msg[1]
                    start_button.config(state="normal")
                    cancel_button.config(state="disabled")
                    state_text = "Cancelled" if cancelled else "Finished"
                    status.set(f"{state_text}.")
                    stats_var.set(f"Recovered: {rec} | Partial: {part} | Bad Sectors: {bad}")
                    messagebox.showinfo(
                        f"Scan {state_text}",
                        f"Recovered files: {rec}\nPartial files: {part}\n"
                        f"Read errors: {bad}\nReport: {report_path}",
                    )
                    return

                elif kind == "error":
                    start_button.config(state="normal")
                    cancel_button.config(state="disabled")
                    status.set("Scan failed.")
                    messagebox.showerror("Recovery error", msg[1])
                    return

        except queue.Empty:
            pass

        root.after(150, poll_queue)

    def start():
        source = image_path.get()
        destination = output_dir.get()

        if not os.path.isfile(source) or not os.path.isdir(destination):
            messagebox.showerror("Invalid selection", "Select a valid image and output folder.")
            return
        try:
            original_source = disk_selector.selected_source()
        except SafetyError as exc:
            messagebox.showerror("Recovery safety", str(exc))
            return

        selected_types = {ext for ext, selected in file_types.items() if selected.get()}
        if not selected_types:
            messagebox.showerror("Invalid selection", "Select at least one file type.")
            return

        cancel_event.clear()
        results_tree.delete(*results_tree.get_children())
        progress_bar["value"] = 0
        start_button.config(state="disabled")
        cancel_button.config(state="normal")
        status.set("Starting scan...")
        threading.Thread(
            target=worker,
            args=(source, destination, selected_types, sector_aligned.get(), original_source),
            daemon=True,
        ).start()
        root.after(150, poll_queue)

    def close_window():
        if str(start_button["state"]) == "disabled" or active_jobs:
            messagebox.showwarning(
                "Scan running", "Cancel the scan and wait for it to finish before closing."
            )
        else:
            root.destroy()

    disk_selector = OriginalDiskSelector(root)
    disk_selector.pack(fill="x", padx=10, pady=5)
    tk.Label(
        root,
        text="Disk identity is supplied by you; image files do not record their original disk. "
             "Hardware RAID and bridges may hide shared physical storage.",
        wraplength=850,
    ).pack()
    tk.Label(root, text="Disk image").pack(anchor="w", padx=10)
    tk.Entry(root, textvariable=image_path, width=70).pack(padx=10)
    tk.Button(root, text="Browse image", command=select_image).pack()

    tk.Label(root, text="Output folder").pack(anchor="w", padx=10)
    tk.Entry(root, textvariable=output_dir, width=70).pack(padx=10)
    tk.Button(root, text="Browse folder", command=select_output).pack()

    options = tk.Frame(root)
    options.pack(pady=5)
    tk.Checkbutton(options, text="Sector-aligned only", variable=sector_aligned).pack(side="left")
    for ext, selected in file_types.items():
        tk.Checkbutton(options, text=ext.upper(), variable=selected).pack(side="left")

    progress_bar = ttk.Progressbar(root, orient="horizontal", length=580, mode="determinate")
    progress_bar.pack(pady=5)

    buttons = tk.Frame(root)
    buttons.pack()
    start_button = tk.Button(buttons, text="Start recovery", command=start)
    start_button.pack(side="left", padx=5)
    cancel_button = tk.Button(
        buttons, text="Cancel", command=cancel_event.set, state="disabled"
    )
    cancel_button.pack(side="left", padx=5)
    tk.Button(
        buttons, text="SMART diagnostics", command=lambda: open_smart_window(root)
    ).pack(side="left", padx=5)
    tk.Button(
        buttons, text="Filesystem recovery",
        command=lambda: open_filesystem_window(root, active_jobs),
    ).pack(side="left", padx=5)

    tk.Label(root, textvariable=status).pack()
    tk.Label(root, textvariable=stats_var).pack()

    columns = ("offset", "type", "status", "bytes", "errors", "path")
    results_tree = ttk.Treeview(root, columns=columns, show="headings", height=10)
    for column, width in (
        ("offset", 80), ("type", 50), ("status", 80),
        ("bytes", 80), ("errors", 55), ("path", 350),
    ):
        results_tree.heading(column, text=column.title())
        results_tree.column(column, width=width)
    results_tree.pack(fill="both", expand=True, padx=10, pady=5)

    root.protocol("WM_DELETE_WINDOW", close_window)
    root.mainloop()


if __name__ == "__main__":
    main()
