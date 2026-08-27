#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import queue
import os
import re
import csv
from datetime import datetime


class SnortSOC(tk.Tk):

    def __init__(self):
        super().__init__()

        # =====================================================
        # WINDOW
        # =====================================================

        self.title("SNORT SOC | Network Intrusion Detection")
        self.geometry("1500x950")
        self.minsize(1100, 700)
        self.configure(bg="#050B12")

        # =====================================================
        # PROCESS / DATA
        # =====================================================

        self.process = None
        self.reader_thread = None
        self.running = False

        self.output_queue = queue.Queue()

        self.alerts = []

        self.total_alerts = 0
        self.high_alerts = 0
        self.medium_alerts = 0
        self.low_alerts = 0

        # =====================================================
        # COLORS
        # =====================================================

        self.BG = "#050B12"
        self.PANEL = "#0A141F"
        self.PANEL2 = "#0D1B28"

        self.TEXT = "#DCEAF5"
        self.MUTED = "#71889A"

        self.GREEN = "#20E3A2"
        self.GREEN_DARK = "#0B5F49"

        self.BLUE = "#3AA7FF"
        self.BLUE_DARK = "#124E78"

        self.PURPLE = "#A56BFF"
        self.PURPLE_DARK = "#54338A"

        self.RED = "#FF4D67"
        self.RED_DARK = "#7A2433"

        self.ORANGE = "#FFB547"
        self.ORANGE_DARK = "#7A5724"

        self.CYAN = "#25D9E8"
        self.CYAN_DARK = "#14606A"

        # =====================================================
        # STYLE
        # =====================================================

        self.create_styles()

        # =====================================================
        # GUI
        # =====================================================

        self.create_gui()

        self.load_default_paths()
        self.detect_interfaces()

        self.after(
            100,
            self.process_queue
        )

        self.protocol(
            "WM_DELETE_WINDOW",
            self.close_application
        )

    # =========================================================
    # STYLE
    # =========================================================

    def create_styles(self):

        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "TButton",
            background="#132536",
            foreground=self.TEXT,
            borderwidth=0,
            padding=(12, 8),
            font=("Segoe UI", 9, "bold")
        )

        style.map(
            "TButton",
            background=[
                ("active", "#1D3C55")
            ]
        )

        style.configure(
            "Start.TButton",
            background=self.GREEN_DARK,
            foreground="white",
            padding=(15, 9),
            font=("Segoe UI", 9, "bold")
        )

        style.map(
            "Start.TButton",
            background=[
                ("active", "#108866")
            ]
        )

        style.configure(
            "Stop.TButton",
            background=self.RED_DARK,
            foreground="white",
            padding=(15, 9),
            font=("Segoe UI", 9, "bold")
        )

        style.map(
            "Stop.TButton",
            background=[
                ("active", "#A62F43")
            ]
        )

        style.configure(
            "Treeview",
            background="#07111A",
            fieldbackground="#07111A",
            foreground=self.TEXT,
            rowheight=32,
            borderwidth=0,
            font=("Segoe UI", 9)
        )

        style.configure(
            "Treeview.Heading",
            background="#112A3C",
            foreground="#9EC4DA",
            relief="flat",
            font=("Segoe UI", 9, "bold")
        )

        style.map(
            "Treeview",
            background=[
                ("selected", "#164C68")
            ],
            foreground=[
                ("selected", "white")
            ]
        )

    # =========================================================
    # PANEL
    # =========================================================

    def create_panel(
        self,
        parent,
        title,
        border_color
    ):
        """
        IMPORTANT:
        This panel uses PACK only inside itself.
        The returned content frame is independent and can
        safely use GRID for its own children.
        """

        outer = tk.Frame(
            parent,
            bg=border_color,
            bd=0
        )

        outer.pack(
            fill="x",
            padx=20,
            pady=6
        )

        inner = tk.Frame(
            outer,
            bg=self.PANEL
        )

        inner.pack(
            fill="both",
            expand=True,
            padx=2,
            pady=2
        )

        # Header uses PACK in header frame
        header = tk.Frame(
            inner,
            bg=self.PANEL
        )

        header.pack(
            fill="x",
            padx=12,
            pady=(9, 5)
        )

        indicator = tk.Frame(
            header,
            bg=border_color,
            width=4,
            height=22
        )

        indicator.pack(
            side="left",
            padx=(0, 8)
        )

        tk.Label(
            header,
            text=title,
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left"
        )

        # This is a NEW frame.
        # It has no pack/grid conflict.
        content = tk.Frame(
            inner,
            bg=self.PANEL
        )

        content.pack(
            fill="both",
            expand=True,
            padx=8,
            pady=(0, 8)
        )

        return content

    # =========================================================
    # GUI
    # =========================================================

    def create_gui(self):

        # =====================================================
        # HEADER
        # =====================================================

        header = tk.Frame(
            self,
            bg=self.BG
        )

        header.pack(
            fill="x",
            padx=20,
            pady=(18, 8)
        )

        title_frame = tk.Frame(
            header,
            bg=self.BG
        )

        title_frame.pack(
            side="left"
        )

        tk.Label(
            title_frame,
            text="SNORT SOC",
            bg=self.BG,
            fg=self.GREEN,
            font=("Segoe UI", 25, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            title_frame,
            text="NETWORK INTRUSION DETECTION & SECURITY MONITORING",
            bg=self.BG,
            fg=self.MUTED,
            font=("Segoe UI", 9)
        ).pack(
            anchor="w"
        )

        # Status
        status_outer = tk.Frame(
            header,
            bg=self.GREEN_DARK
        )

        status_outer.pack(
            side="right"
        )

        status_inner = tk.Frame(
            status_outer,
            bg="#0A1C19"
        )

        status_inner.pack(
            padx=2,
            pady=2
        )

        self.status_text = tk.StringVar(
            value="● OFFLINE"
        )

        self.status_label = tk.Label(
            status_inner,
            textvariable=self.status_text,
            bg="#0A1C19",
            fg=self.RED,
            font=("Segoe UI", 10, "bold"),
            padx=18,
            pady=8
        )

        self.status_label.pack()

        # =====================================================
        # CONFIGURATION
        # =====================================================

        config = self.create_panel(
            self,
            "SNORT CONFIGURATION",
            self.BLUE
        )

        config.columnconfigure(0, weight=1)
        config.columnconfigure(1, weight=0)
        config.columnconfigure(2, weight=2)
        config.columnconfigure(3, weight=0)
        config.columnconfigure(4, weight=2)
        config.columnconfigure(5, weight=0)

        # Interface label
        tk.Label(
            config,
            text="NETWORK INTERFACE",
            bg=self.PANEL,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold")
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=6,
            pady=(3, 4)
        )

        # Interface
        self.interface_var = tk.StringVar()

        self.interface_combo = ttk.Combobox(
            config,
            textvariable=self.interface_var,
            state="readonly"
        )

        self.interface_combo.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=6,
            pady=(0, 10)
        )

        ttk.Button(
            config,
            text="⟳ REFRESH",
            command=self.detect_interfaces
        ).grid(
            row=1,
            column=1,
            padx=6,
            pady=(0, 10)
        )

        # Config label
        tk.Label(
            config,
            text="SNORT CONFIGURATION",
            bg=self.PANEL,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold")
        ).grid(
            row=0,
            column=2,
            sticky="w",
            padx=6,
            pady=(3, 4)
        )

        self.config_var = tk.StringVar()

        config_entry = tk.Entry(
            config,
            textvariable=self.config_var,
            bg="#07111A",
            fg=self.TEXT,
            insertbackground=self.GREEN,
            relief="flat",
            font=("Consolas", 9)
        )

        config_entry.grid(
            row=1,
            column=2,
            sticky="ew",
            padx=6,
            pady=(0, 10)
        )

        ttk.Button(
            config,
            text="BROWSE",
            command=self.browse_config
        ).grid(
            row=1,
            column=3,
            padx=6,
            pady=(0, 10)
        )

        # Rules label
        tk.Label(
            config,
            text="LOCAL RULES",
            bg=self.PANEL,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold")
        ).grid(
            row=0,
            column=4,
            sticky="w",
            padx=6,
            pady=(3, 4)
        )

        self.rules_var = tk.StringVar()

        rules_entry = tk.Entry(
            config,
            textvariable=self.rules_var,
            bg="#07111A",
            fg=self.TEXT,
            insertbackground=self.GREEN,
            relief="flat",
            font=("Consolas", 9)
        )

        rules_entry.grid(
            row=1,
            column=4,
            sticky="ew",
            padx=6,
            pady=(0, 10)
        )

        ttk.Button(
            config,
            text="BROWSE",
            command=self.browse_rules
        ).grid(
            row=1,
            column=5,
            padx=6,
            pady=(0, 10)
        )

        # =====================================================
        # CONTROLS
        # =====================================================

        controls = self.create_panel(
            self,
            "MONITORING CONTROLS",
            self.PURPLE
        )

        self.start_button = ttk.Button(
            controls,
            text="▶  START MONITORING",
            style="Start.TButton",
            command=self.start_snort
        )

        self.start_button.pack(
            side="left",
            padx=6,
            pady=5
        )

        self.stop_button = ttk.Button(
            controls,
            text="■  STOP MONITORING",
            style="Stop.TButton",
            command=self.stop_snort
        )

        self.stop_button.pack(
            side="left",
            padx=6,
            pady=5
        )

        self.stop_button.state(
            ["disabled"]
        )

        ttk.Button(
            controls,
            text="⚙ TEST SNORT",
            command=self.test_snort
        ).pack(
            side="left",
            padx=6,
            pady=5
        )

        ttk.Button(
            controls,
            text="✕ CLEAR ALERTS",
            command=self.clear_alerts
        ).pack(
            side="left",
            padx=6,
            pady=5
        )

        ttk.Button(
            controls,
            text="⇩ EXPORT CSV",
            command=self.export_csv
        ).pack(
            side="left",
            padx=6,
            pady=5
        )

        # =====================================================
        # STATISTICS
        # =====================================================

        stats = tk.Frame(
            self,
            bg=self.BG
        )

        stats.pack(
            fill="x",
            padx=20,
            pady=6
        )

        self.total_label = self.create_stat_card(
            stats,
            "TOTAL ALERTS",
            "0",
            self.GREEN
        )

        self.high_label = self.create_stat_card(
            stats,
            "HIGH PRIORITY",
            "0",
            self.RED
        )

        self.medium_label = self.create_stat_card(
            stats,
            "MEDIUM PRIORITY",
            "0",
            self.ORANGE
        )

        self.low_label = self.create_stat_card(
            stats,
            "LOW PRIORITY",
            "0",
            self.BLUE
        )

        # =====================================================
        # ALERTS
        # =====================================================

        alert_outer = tk.Frame(
            self,
            bg=self.RED
        )

        alert_outer.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=6
        )

        alert_inner = tk.Frame(
            alert_outer,
            bg=self.PANEL
        )

        alert_inner.pack(
            fill="both",
            expand=True,
            padx=2,
            pady=2
        )

        alert_header = tk.Frame(
            alert_inner,
            bg=self.PANEL
        )

        alert_header.pack(
            fill="x",
            padx=12,
            pady=8
        )

        tk.Frame(
            alert_header,
            bg=self.RED,
            width=4,
            height=22
        ).pack(
            side="left",
            padx=(0, 8)
        )

        tk.Label(
            alert_header,
            text="LIVE SECURITY ALERTS",
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left"
        )

        table_frame = tk.Frame(
            alert_inner,
            bg=self.PANEL
        )

        table_frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        columns = (
            "time",
            "priority",
            "message",
            "protocol",
            "source",
            "destination",
            "sid"
        )

        self.alert_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        headings = {
            "time": "TIME",
            "priority": "PRI",
            "message": "ALERT MESSAGE",
            "protocol": "PROTO",
            "source": "SOURCE",
            "destination": "DESTINATION",
            "sid": "SID"
        }

        widths = {
            "time": 90,
            "priority": 55,
            "message": 400,
            "protocol": 75,
            "source": 180,
            "destination": 180,
            "sid": 90
        }

        for column in columns:

            self.alert_table.heading(
                column,
                text=headings[column]
            )

            self.alert_table.column(
                column,
                width=widths[column],
                minwidth=50,
                anchor="center"
            )

        self.alert_table.column(
            "message",
            anchor="w"
        )

        self.alert_table.tag_configure(
            "high",
            foreground=self.RED
        )

        self.alert_table.tag_configure(
            "medium",
            foreground=self.ORANGE
        )

        self.alert_table.tag_configure(
            "low",
            foreground=self.BLUE
        )

        vertical = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.alert_table.yview
        )

        horizontal = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.alert_table.xview
        )

        self.alert_table.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set
        )

        self.alert_table.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        vertical.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        horizontal.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        table_frame.rowconfigure(
            0,
            weight=1
        )

        table_frame.columnconfigure(
            0,
            weight=1
        )

        # =====================================================
        # CONSOLE
        # =====================================================

        console_outer = tk.Frame(
            self,
            bg=self.CYAN
        )

        console_outer.pack(
            fill="x",
            padx=20,
            pady=6
        )

        console_inner = tk.Frame(
            console_outer,
            bg=self.PANEL
        )

        console_inner.pack(
            fill="both",
            expand=True,
            padx=2,
            pady=2
        )

        console_header = tk.Frame(
            console_inner,
            bg=self.PANEL
        )

        console_header.pack(
            fill="x",
            padx=12,
            pady=7
        )

        tk.Frame(
            console_header,
            bg=self.CYAN,
            width=4,
            height=22
        ).pack(
            side="left",
            padx=(0, 8)
        )

        tk.Label(
            console_header,
            text="SNORT CONSOLE OUTPUT",
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left"
        )

        console_frame = tk.Frame(
            console_inner,
            bg="#02070B"
        )

        console_frame.pack(
            fill="x",
            padx=10,
            pady=(0, 10)
        )

        self.console = tk.Text(
            console_frame,
            height=7,
            bg="#02070B",
            fg="#8EB8CE",
            insertbackground=self.GREEN,
            relief="flat",
            wrap="none",
            font=("Consolas", 9)
        )

        console_scroll = ttk.Scrollbar(
            console_frame,
            orient="vertical",
            command=self.console.yview
        )

        self.console.configure(
            yscrollcommand=console_scroll.set
        )

        self.console.pack(
            side="left",
            fill="both",
            expand=True
        )

        console_scroll.pack(
            side="right",
            fill="y"
        )

        # =====================================================
        # FOOTER
        # =====================================================

        footer = tk.Frame(
            self,
            bg=self.BG
        )

        footer.pack(
            fill="x",
            padx=20,
            pady=(0, 8)
        )

        tk.Label(
            footer,
            text="SNORT SOC LAB",
            bg=self.BG,
            fg=self.GREEN,
            font=("Segoe UI", 8, "bold")
        ).pack(
            side="left"
        )

        tk.Label(
            footer,
            text=" | Network Intrusion Detection | Authorized Monitoring Only",
            bg=self.BG,
            fg=self.MUTED,
            font=("Segoe UI", 8)
        ).pack(
            side="left"
        )

        tk.Label(
            footer,
            text="v2.1",
            bg=self.BG,
            fg=self.MUTED,
            font=("Segoe UI", 8)
        ).pack(
            side="right"
        )

    # =========================================================
    # STAT CARD
    # =========================================================

    def create_stat_card(
        self,
        parent,
        title,
        value,
        color
    ):

        outer = tk.Frame(
            parent,
            bg=color
        )

        outer.pack(
            side="left",
            fill="x",
            expand=True,
            padx=4
        )

        inner = tk.Frame(
            outer,
            bg=self.PANEL
        )

        inner.pack(
            fill="both",
            expand=True,
            padx=2,
            pady=2
        )

        tk.Label(
            inner,
            text=title,
            bg=self.PANEL,
            fg=self.MUTED,
            font=("Segoe UI", 8, "bold")
        ).pack(
            anchor="w",
            padx=12,
            pady=(7, 0)
        )

        label = tk.Label(
            inner,
            text=value,
            bg=self.PANEL,
            fg=color,
            font=("Segoe UI", 22, "bold")
        )

        label.pack(
            anchor="w",
            padx=12,
            pady=(0, 7)
        )

        return label

    # =========================================================
    # DEFAULT PATHS
    # =========================================================

    def load_default_paths(self):

        config_paths = [
            "/etc/snort/snort.lua",
            "/usr/local/etc/snort/snort.lua"
        ]

        rule_paths = [
            "/etc/snort/rules/local.rules",
            "/usr/local/etc/snort/rules/local.rules"
        ]

        config = next(
            (
                path
                for path in config_paths
                if os.path.isfile(path)
            ),
            config_paths[0]
        )

        rules = next(
            (
                path
                for path in rule_paths
                if os.path.isfile(path)
            ),
            rule_paths[0]
        )

        self.config_var.set(
            config
        )

        self.rules_var.set(
            rules
        )

    # =========================================================
    # INTERFACES
    # =========================================================

    def detect_interfaces(self):

        interfaces = []

        try:

            result = subprocess.run(
                ["ip", "-br", "link"],
                capture_output=True,
                text=True,
                timeout=5
            )

            for line in result.stdout.splitlines():

                parts = line.split()

                if not parts:
                    continue

                interface = parts[0]

                if interface != "lo":

                    interfaces.append(
                        interface
                    )

        except Exception as error:

            self.console_write(
                "[Interface Error] "
                + str(error)
                + "\n"
            )

        if not interfaces:

            interfaces = [
                "eth0",
                "wlan0",
                "ens33"
            ]

        self.interface_combo["values"] = interfaces

        if interfaces:

            self.interface_var.set(
                interfaces[0]
            )

    # =========================================================
    # BROWSE CONFIG
    # =========================================================

    def browse_config(self):

        filename = filedialog.askopenfilename(
            title="Select Snort Configuration",
            filetypes=[
                ("Snort Lua Config", "*.lua"),
                ("All Files", "*.*")
            ]
        )

        if filename:

            self.config_var.set(
                filename
            )

    # =========================================================
    # BROWSE RULES
    # =========================================================

    def browse_rules(self):

        filename = filedialog.askopenfilename(
            title="Select Snort Rules",
            filetypes=[
                ("Snort Rules", "*.rules"),
                ("All Files", "*.*")
            ]
        )

        if filename:

            self.rules_var.set(
                filename
            )

    # =========================================================
    # SNORT COMMAND
    # =========================================================

    def get_snort_command(self):

        interface = self.interface_var.get().strip()
        config = self.config_var.get().strip()
        rules = self.rules_var.get().strip()

        if not interface:

            raise ValueError(
                "Please select a network interface."
            )

        if not os.path.isfile(config):

            raise ValueError(
                "Snort configuration file not found:\n\n"
                + config
            )

        if not os.path.isfile(rules):

            raise ValueError(
                "Snort rules file not found:\n\n"
                + rules
            )

        return [
            "snort",
            "-q",
            "-c",
            config,
            "-R",
            rules,
            "-i",
            interface,
            "-A",
            "alert_fast"
        ]

    # =========================================================
    # START
    # =========================================================

    def start_snort(self):

        if self.running:

            return

        try:

            command = self.get_snort_command()

        except ValueError as error:

            messagebox.showerror(
                "Configuration Error",
                str(error)
            )

            return

        self.console_write(
            "\n$ "
            + " ".join(command)
            + "\n"
        )

        self.console_write(
            "[*] Starting Snort monitoring...\n"
        )

        try:

            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

        except FileNotFoundError:

            messagebox.showerror(
                "Snort Error",
                "Snort executable was not found.\n\n"
                "Check that Snort is installed."
            )

            return

        except Exception as error:

            messagebox.showerror(
                "Snort Error",
                str(error)
            )

            return

        self.running = True

        self.status_text.set(
            "● MONITORING"
        )

        self.status_label.configure(
            fg=self.GREEN
        )

        self.start_button.state(
            ["disabled"]
        )

        self.stop_button.state(
            ["!disabled"]
        )

        self.reader_thread = threading.Thread(
            target=self.read_output,
            daemon=True
        )

        self.reader_thread.start()

    # =========================================================
    # READ OUTPUT
    # =========================================================

    def read_output(self):

        try:

            while True:

                line = self.process.stdout.readline()

                if not line:

                    break

                self.output_queue.put(
                    (
                        "output",
                        line.rstrip()
                    )
                )

        except Exception as error:

            self.output_queue.put(
                (
                    "output",
                    "[Reader Error] " + str(error)
                )
            )

        self.output_queue.put(
            (
                "stopped",
                None
            )
        )

    # =========================================================
    # STOP
    # =========================================================

    def stop_snort(self):

        if self.process is None:

            return

        try:

            if self.process.poll() is None:

                self.process.terminate()

                try:

                    self.process.wait(
                        timeout=5
                    )

                except subprocess.TimeoutExpired:

                    self.process.kill()

        except Exception as error:

            self.console_write(
                "[Stop Error] "
                + str(error)
                + "\n"
            )

        self.process = None
        self.running = False

        self.status_text.set(
            "● OFFLINE"
        )

        self.status_label.configure(
            fg=self.RED
        )

        self.start_button.state(
            ["!disabled"]
        )

        self.stop_button.state(
            ["disabled"]
        )

        self.console_write(
            "[*] Snort stopped.\n"
        )

    # =========================================================
    # TEST
    # =========================================================

    def test_snort(self):

        config = self.config_var.get().strip()
        rules = self.rules_var.get().strip()

        if not os.path.isfile(config):

            messagebox.showerror(
                "Error",
                "Snort configuration file not found."
            )

            return

        if not os.path.isfile(rules):

            messagebox.showerror(
                "Error",
                "Rules file not found."
            )

            return

        command = [
            "snort",
            "-T",
            "-c",
            config,
            "-R",
            rules
        ]

        self.console_write(
            "\n$ "
            + " ".join(command)
            + "\n"
        )

        self.console_write(
            "[*] Testing Snort configuration...\n"
        )

        def worker():

            try:

                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30
                )

                self.output_queue.put(
                    (
                        "test",
                        (
                            result.returncode,
                            result.stdout
                        )
                    )
                )

            except Exception as error:

                self.output_queue.put(
                    (
                        "test",
                        (
                            1,
                            str(error)
                        )
                    )
                )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    # =========================================================
    # QUEUE
    # =========================================================

    def process_queue(self):

        try:

            while True:

                event, data = (
                    self.output_queue.get_nowait()
                )

                if event == "output":

                    self.handle_snort_line(
                        data
                    )

                elif event == "test":

                    return_code, output = data

                    self.console_write(
                        output
                    )

                    if return_code == 0:

                        messagebox.showinfo(
                            "Snort Test",
                            "Snort configuration test passed."
                        )

                    else:

                        messagebox.showerror(
                            "Snort Test",
                            "Snort configuration test failed.\n"
                            "Check the console output."
                        )

                elif event == "stopped":

                    if self.running:

                        self.running = False

                        self.status_text.set(
                            "● OFFLINE"
                        )

                        self.status_label.configure(
                            fg=self.RED
                        )

                        self.start_button.state(
                            ["!disabled"]
                        )

                        self.stop_button.state(
                            ["disabled"]
                        )

        except queue.Empty:

            pass

        self.after(
            100,
            self.process_queue
        )

    # =========================================================
    # SNORT LINE
    # =========================================================

    def handle_snort_line(self, line):

        self.console_write(
            line + "\n"
        )

        if "[**]" not in line:

            return

        priority = self.extract_priority(
            line
        )

        sid = self.extract_sid(
            line
        )

        message = self.extract_message(
            line
        )

        protocol = self.extract_protocol(
            line
        )

        source, destination = (
            self.extract_addresses(line)
        )

        classification = (
            self.extract_classification(line)
        )

        self.add_alert(
            priority,
            message,
            protocol,
            source,
            destination,
            sid,
            classification
        )

    # =========================================================
    # PARSING
    # =========================================================

    def extract_priority(self, line):

        match = re.search(
            r"\[Priority:\s*(\d+)\]",
            line
        )

        if match:

            return int(
                match.group(1)
            )

        return 2

    def extract_sid(self, line):

        match = re.search(
            r"\[(\d+):(\d+):(\d+)\]",
            line
        )

        if match:

            return match.group(2)

        return "-"

    def extract_message(self, line):

        match = re.search(
            r'\[\*\*\]\s*\[[^]]+\]\s*(?:\[[^]]+\]\s*)?"([^"]+)"',
            line
        )

        if match:

            return match.group(1)

        return "Snort Alert"

    def extract_protocol(self, line):

        match = re.search(
            r"\{([^}]+)\}",
            line
        )

        if match:

            return match.group(1)

        return "-"

    def extract_addresses(self, line):

        match = re.search(
            r"\}\s+(\S+)\s+->\s+(\S+)",
            line
        )

        if match:

            return (
                match.group(1),
                match.group(2)
            )

        return (
            "-",
            "-"
        )

    def extract_classification(self, line):

        match = re.search(
            r"\[Classification:\s*([^\]]+)\]",
            line
        )

        if match:

            return match.group(1)

        return "Unknown"

    # =========================================================
    # ADD ALERT
    # =========================================================

    def add_alert(
        self,
        priority,
        message,
        protocol,
        source,
        destination,
        sid,
        classification
    ):

        if priority == 1:

            tag = "high"
            self.high_alerts += 1

        elif priority == 2:

            tag = "medium"
            self.medium_alerts += 1

        else:

            tag = "low"
            self.low_alerts += 1

        self.total_alerts += 1

        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )

        alert = {
            "time": timestamp,
            "priority": priority,
            "message": message,
            "protocol": protocol,
            "source": source,
            "destination": destination,
            "sid": sid,
            "classification": classification
        }

        self.alerts.append(
            alert
        )

        self.alert_table.insert(
            "",
            0,
            values=(
                timestamp,
                priority,
                message,
                protocol,
                source,
                destination,
                sid
            ),
            tags=(tag,)
        )

        self.update_statistics()

    # =========================================================
    # STATISTICS
    # =========================================================

    def update_statistics(self):

        self.total_label.configure(
            text=str(
                self.total_alerts
            )
        )

        self.high_label.configure(
            text=str(
                self.high_alerts
            )
        )

        self.medium_label.configure(
            text=str(
                self.medium_alerts
            )
        )

        self.low_label.configure(
            text=str(
                self.low_alerts
            )
        )

    # =========================================================
    # CONSOLE
    # =========================================================

    def console_write(self, text):

        self.console.insert(
            "end",
            text
        )

        self.console.see(
            "end"
        )

    # =========================================================
    # CLEAR
    # =========================================================

    def clear_alerts(self):

        for item in self.alert_table.get_children():

            self.alert_table.delete(
                item
            )

        self.alerts.clear()

        self.total_alerts = 0
        self.high_alerts = 0
        self.medium_alerts = 0
        self.low_alerts = 0

        self.update_statistics()

        self.console_write(
            "[*] Alert table cleared.\n"
        )

    # =========================================================
    # EXPORT
    # =========================================================

    def export_csv(self):

        if not self.alerts:

            messagebox.showinfo(
                "Export",
                "There are no alerts to export."
            )

            return

        filename = filedialog.asksaveasfilename(
            title="Export Snort Alerts",
            defaultextension=".csv",
            filetypes=[
                ("CSV Files", "*.csv")
            ]
        )

        if not filename:

            return

        try:

            fields = [
                "time",
                "priority",
                "message",
                "protocol",
                "source",
                "destination",
                "sid",
                "classification"
            ]

            with open(
                filename,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.DictWriter(
                    file,
                    fieldnames=fields
                )

                writer.writeheader()
                writer.writerows(
                    self.alerts
                )

            messagebox.showinfo(
                "Export",
                "Alerts exported successfully."
            )

        except Exception as error:

            messagebox.showerror(
                "Export Error",
                str(error)
            )

    # =========================================================
    # CLOSE
    # =========================================================

    def close_application(self):

        if self.running:

            self.stop_snort()

        self.destroy()


# =============================================================
# MAIN
# =============================================================

if __name__ == "__main__":

    app = SnortSOC()

    app.mainloop()
