import socket
import threading
import time
import queue
import sys
import subprocess
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ---------------------------
# Service Map (extend freely)
# ---------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
}

# ---------------------------
# Port Presets
# ---------------------------
PORT_PRESETS = {
    "Top 20":  (1, 1024),
    "Web":     (80, 8443),
    "Database":(3306, 5432),
    "Common":  (1, 65535),
}

# ---------------------------
# Scanner Worker
# ---------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=500):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()

        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []            # list[(port, service, banner)]
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        self._stop_event.set()

    # NEW: attempt to grab a service banner from an open port
    def _grab_banner(self, sock):
        try:
            sock.settimeout(1.0)
            # Send a generic probe; some services respond unsolicited
            sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
        except Exception:
            pass
        try:
            data = sock.recv(256)
            banner = data.decode('utf-8', errors='replace').strip()
            # Return first meaningful line only
            first_line = banner.splitlines()[0] if banner else ''
            return first_line[:80]  # cap at 80 chars
        except Exception:
            return ''

    def _scan_port(self, port):
        if self._stop_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                # NEW: try banner grab on success
                banner = self._grab_banner(s)
                with self._lock:
                    self.open_ports.append((port, service, banner))
                self.result_queue.put(('open', port, service, banner))
            s.close()
        except Exception as e:
            self.result_queue.put(('error', port, str(e), ''))
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports, ''))

    def resolve_target(self):
        return socket.gethostbyname(self.target)

    def run(self):
        sem = threading.Semaphore(self.max_workers)
        threads = []

        for port in range(self.start_port, self.end_port + 1):
            if self._stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._worker_wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.result_queue.put(('done', None, None, None))

    def _worker_wrapper(self, sem, port):
        try:
            self._scan_port(port)
        finally:
            sem.release()


# ---------------------------
# NEW: Ping helper (cross-platform)
# ---------------------------
def ping_host(host):
    """Returns True if host responds to ping, False otherwise."""
    try:
        flag = '-n' if sys.platform.startswith('win') else '-c'
        result = subprocess.run(
            ['ping', flag, '1', '-W', '1', host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False  # treat failure as inconclusive, don't block scan


# ---------------------------
# Tkinter GUI – enhanced
# ---------------------------
class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Port Scanner – Sk Naimuddin")
        self.geometry("800x620")
        self.minsize(720, 540)

        self.scanner_thread = None
        self.scanner = None
        self.start_time = None
        self.poll_after_ms = 40

        # NEW: session history storage  [(timestamp, target, range, open_count)]
        self.scan_history = []

        self._build_ui()

    def _build_ui(self):
        # --- Top Frame: Inputs ---
        frm_top = ttk.LabelFrame(self, text="Scan Settings")
        frm_top.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm_top, text="Target (IP / Hostname):").grid(row=0, column=0, padx=8, pady=8, sticky="e")
        self.ent_target = ttk.Entry(frm_top, width=30)
        self.ent_target.grid(row=0, column=1, padx=8, pady=8, sticky="w")

        ttk.Label(frm_top, text="Start Port:").grid(row=0, column=2, padx=8, pady=8, sticky="e")
        self.ent_start = ttk.Entry(frm_top, width=8)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=0, column=3, padx=8, pady=8, sticky="w")

        ttk.Label(frm_top, text="End Port:").grid(row=0, column=4, padx=8, pady=8, sticky="e")
        self.ent_end = ttk.Entry(frm_top, width=8)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=0, column=5, padx=8, pady=8, sticky="w")

        # NEW: Preset buttons row
        frm_presets = ttk.Frame(frm_top)
        frm_presets.grid(row=1, column=0, columnspan=6, padx=8, pady=(0, 8), sticky="w")
        ttk.Label(frm_presets, text="Presets:").pack(side="left", padx=(0, 6))
        for label, (s, e) in PORT_PRESETS.items():
            ttk.Button(
                frm_presets, text=label,
                command=lambda s=s, e=e: self._apply_preset(s, e)
            ).pack(side="left", padx=3)

        self.btn_start = ttk.Button(frm_top, text="Start Scan", command=self.start_scan)
        self.btn_start.grid(row=2, column=4, padx=8, pady=8, sticky="e")

        self.btn_stop = ttk.Button(frm_top, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=2, column=5, padx=8, pady=8, sticky="w")

        for i in range(6):
            frm_top.grid_columnconfigure(i, weight=1)

        # --- Progress / Status ---
        frm_status = ttk.LabelFrame(self, text="Status")
        frm_status.pack(fill="x", padx=10, pady=(0, 10))

        self.var_status = tk.StringVar(value="Idle")
        self.lbl_status = ttk.Label(frm_status, textvariable=self.var_status)
        self.lbl_status.pack(side="left", padx=10, pady=8)

        self.var_elapsed = tk.StringVar(value="Elapsed: 0.00s")
        self.lbl_elapsed = ttk.Label(frm_status, textvariable=self.var_elapsed)
        self.lbl_elapsed.pack(side="right", padx=10, pady=8)

        self.progress = ttk.Progressbar(frm_status, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0, 10))

        # --- NEW: Notebook with Results + History tabs ---
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Tab 1: Open Ports
        frm_results = ttk.Frame(self.notebook)
        self.notebook.add(frm_results, text="Open Ports")

        self.txt_results = tk.Text(
            frm_results, height=14, wrap="none",
            font=("Consolas", 10)
        )
        self.txt_results.pack(fill="both", expand=True, side="left", padx=(10, 0), pady=10)

        # NEW: color tags for the results text widget
        self.txt_results.tag_configure("open_port", foreground="#2a9d3c", font=("Consolas", 10, "bold"))
        self.txt_results.tag_configure("known_service", foreground="#1a5fb4")
        self.txt_results.tag_configure("banner", foreground="#7a5c00")
        self.txt_results.tag_configure("info", foreground="#555555")
        self.txt_results.tag_configure("error_tag", foreground="#c0392b")

        yscroll = ttk.Scrollbar(frm_results, orient="vertical", command=self.txt_results.yview)
        yscroll.pack(side="right", fill="y", pady=10)
        self.txt_results.configure(yscrollcommand=yscroll.set)

        xscroll = ttk.Scrollbar(self, orient="horizontal", command=self.txt_results.xview)
        xscroll.pack(fill="x", padx=10, pady=(0, 2))
        self.txt_results.configure(xscrollcommand=xscroll.set)

        # Tab 2: Scan History
        frm_history = ttk.Frame(self.notebook)
        self.notebook.add(frm_history, text="Scan History")

        cols = ("Time", "Target", "Port Range", "Open Ports", "Duration")
        self.tree_history = ttk.Treeview(frm_history, columns=cols, show="headings", height=12)
        for col in cols:
            self.tree_history.heading(col, text=col)
            self.tree_history.column(col, width=130, anchor="center")
        self.tree_history.pack(fill="both", expand=True, padx=10, pady=10)

        hist_scroll = ttk.Scrollbar(frm_history, orient="vertical", command=self.tree_history.yview)
        hist_scroll.pack(side="right", fill="y")
        self.tree_history.configure(yscrollcommand=hist_scroll.set)

        # --- Bottom Buttons ---
        frm_bottom = ttk.Frame(self)
        frm_bottom.pack(fill="x", padx=10, pady=(0, 12))

        self.btn_clear = ttk.Button(frm_bottom, text="Clear", command=self.clear_results)
        self.btn_clear.pack(side="left", padx=(0, 6))

        # NEW: Clear history button
        ttk.Button(frm_bottom, text="Clear History", command=self.clear_history).pack(side="left")

        self.btn_save = ttk.Button(frm_bottom, text="Save as TXT", command=self.save_results_txt, state="disabled")
        self.btn_save.pack(side="right", padx=(6, 0))

        # NEW: Save as CSV button
        self.btn_save_csv = ttk.Button(frm_bottom, text="Save as CSV", command=self.save_results_csv, state="disabled")
        self.btn_save_csv.pack(side="right", padx=(6, 0))

    # -----------------------
    # NEW: Preset handler
    # -----------------------
    def _apply_preset(self, start, end):
        self.ent_start.delete(0, tk.END)
        self.ent_start.insert(0, str(start))
        self.ent_end.delete(0, tk.END)
        self.ent_end.insert(0, str(end))

    # -----------------------
    # Control Handlers
    # -----------------------
    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            messagebox.showinfo("Scanner", "A scan is already running.")
            return

        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
            return

        try:
            start_port = int(self.ent_start.get().strip())
            end_port = int(self.ent_end.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Ports must be integers.")
            return

        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port):
            messagebox.showerror("Input Error", "Port range must be within 0–65535 and start ≤ end.")
            return

        # NEW: Ping/reachability check (non-blocking warning)
        self.append_text(f"Checking reachability of {target}...\n", "info")
        self.update_idletasks()
        reachable = ping_host(target)
        if not reachable:
            proceed = messagebox.askyesno(
                "Host Unreachable",
                f"'{target}' did not respond to ping.\n\n"
                "The host may be firewalled, offline, or blocking ICMP.\n"
                "Do you still want to proceed with the port scan?"
            )
            if not proceed:
                self.txt_results.delete("1.0", tk.END)
                self.var_status.set("Idle")
                return
        else:
            self.append_text("Host is reachable.\n", "info")

        timeout = 0.5
        max_threads = 500

        self.scanner = PortScanner(target, start_port, end_port, timeout=timeout, max_workers=max_threads)

        try:
            resolved_ip = self.scanner.resolve_target()
            self.append_text(f"Target: {target} ({resolved_ip})\n", "info")
            self.append_text(f"Range: {start_port}–{end_port}\n\n", "info")
        except Exception as e:
            messagebox.showerror("Resolution Error", f"Failed to resolve target '{target}'.\n{e}")
            self.scanner = None
            return

        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_save.configure(state="disabled")
        self.btn_save_csv.configure(state="disabled")
        self.clear_progress()

        # Store scan start info for history
        self._scan_start_time = time.time()
        self._scan_meta = (target, start_port, end_port)

        self.start_time = time.time()
        self.var_status.set("Scanning...")
        self.update_elapsed()

        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()

        self.after(self.poll_after_ms, self.poll_results)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.var_status.set("Stopping...")

    def clear_results(self):
        self.txt_results.delete("1.0", tk.END)
        self.clear_progress()
        self.var_status.set("Idle")
        self.var_elapsed.set("Elapsed: 0.00s")
        self.btn_save.configure(state="disabled")
        self.btn_save_csv.configure(state="disabled")

    # NEW: Clear scan history
    def clear_history(self):
        self.scan_history.clear()
        for row in self.tree_history.get_children():
            self.tree_history.delete(row)

    # NEW: add a row to the history tab
    def _add_history_entry(self, target, start_port, end_port, open_count, duration):
        ts = time.strftime("%H:%M:%S")
        port_range = f"{start_port}–{end_port}"
        duration_str = f"{duration:.1f}s"
        self.scan_history.append((ts, target, port_range, open_count, duration_str))
        self.tree_history.insert("", "end", values=(ts, target, port_range, open_count, duration_str))

    # -----------------------
    # Save handlers
    # -----------------------
    def save_results_txt(self):
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showinfo("Save Results", "No open ports to save.")
            return

        default_name = f"open_ports_{int(time.time())}.txt"
        file_path = filedialog.asksaveasfilename(
            title="Save results as TXT",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("Open Ports:\n")
                for port, service, banner in sorted(self.scanner.open_ports, key=lambda x: x[0]):
                    line = f"Port {port} ({service}) is open"
                    if banner:
                        line += f"  |  Banner: {banner}"
                    f.write(line + "\n")
            messagebox.showinfo("Saved", f"Results saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save file.\n{e}")

    # NEW: Save results as CSV
    def save_results_csv(self):
        if not self.scanner or not self.scanner.open_ports:
            messagebox.showinfo("Save Results", "No open ports to save.")
            return

        default_name = f"open_ports_{int(time.time())}.csv"
        file_path = filedialog.asksaveasfilename(
            title="Save results as CSV",
            defaultextension=".csv",
            initialfile=default_name,
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Port", "Service", "Banner"])
                for port, service, banner in sorted(self.scanner.open_ports, key=lambda x: x[0]):
                    writer.writerow([port, service, banner or ""])
            messagebox.showinfo("Saved", f"CSV saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save CSV.\n{e}")

    # -----------------------
    # UI Helpers
    # -----------------------
    def append_text(self, text, tag=None):
        self.txt_results.insert(tk.END, text, tag or "")
        self.txt_results.see(tk.END)

    def clear_progress(self):
        self.progress.configure(value=0, maximum=1)

    def update_elapsed(self):
        if self.start_time and self.var_status.get() in ("Scanning...", "Stopping..."):
            elapsed = time.time() - self.start_time
            self.var_elapsed.set(f"Elapsed: {elapsed:.2f}s")
            self.after(200, self.update_elapsed)

    def poll_results(self):
        if not self.scanner:
            return

        try:
            while True:
                msg_type, a, b, banner = self.scanner.result_queue.get_nowait()
                if msg_type == 'open':
                    port, service = a, b
                    # NEW: color-coded output
                    self.append_text(f"[+] Port {port}", "open_port")
                    known = service != 'Unknown'
                    self.append_text(f" ({service})", "known_service" if known else "")
                    self.append_text(" is open", "open_port")
                    if banner:
                        self.append_text(f"\n    Banner: {banner}", "banner")
                    self.append_text("\n")
                elif msg_type == 'progress':
                    scanned, total = a, b
                    self.progress.configure(maximum=max(total, 1), value=scanned)
                    self.var_status.set(f"Scanning... {scanned}/{total}")
                elif msg_type == 'done':
                    total_open = len(self.scanner.open_ports)
                    elapsed = time.time() - self._scan_start_time
                    self.append_text("\nScan complete.\n", "info")
                    self.append_text(f"Open ports found: {total_open}\n", "info")
                    self.var_status.set("Completed")
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    has_results = total_open > 0
                    self.btn_save.configure(state="normal" if has_results else "disabled")
                    self.btn_save_csv.configure(state="normal" if has_results else "disabled")
                    self.start_time = None
                    # NEW: record history
                    target, sp, ep = self._scan_meta
                    self._add_history_entry(target, sp, ep, total_open, elapsed)
        except queue.Empty:
            pass

        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.poll_after_ms, self.poll_results)
        else:
            if self.var_status.get() in ("Scanning...", "Stopping..."):
                self.var_status.set("Completed")
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            if self.scanner and self.scanner.open_ports:
                self.btn_save.configure(state="normal")
                self.btn_save_csv.configure(state="normal")


def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 7)
        except Exception:
            pass

    app = ScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
