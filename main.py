import json
import os
import shutil
import threading
import webbrowser
from datetime import datetime
from tkinter import Listbox, MULTIPLE, END, Scrollbar, messagebox
import tkinter as tk

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
LOCAL_JSON_FILE = os.path.join(BASE_DIR, "vulnerabilities.json")
PREVIOUS_JSON_FILE = os.path.join(BASE_DIR, "previous_vulnerabilities.json")
SELECTED_VENDORS_FILE = os.path.join(BASE_DIR, "selected_vendors.json")
AUTO_REFRESH_MS = 60 * 60 * 1000  # 1 hour


def fetch_vulnerabilities():
    response = requests.get(JSON_URL, timeout=30)
    response.raise_for_status()
    return response.json()["vulnerabilities"]


def load_data_from_file(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def save_data_to_file(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


def compare_vulnerabilities(current, previous):
    previous_ids = {item["cveID"] for item in previous}
    return [item for item in current if item["cveID"] not in previous_ids]


def load_selected_vendors():
    data = load_data_from_file(SELECTED_VENDORS_FILE)
    if isinstance(data, dict):
        return data.get("vendors", [])
    return []


def save_selected_vendors(vendors):
    save_data_to_file({"vendors": vendors}, SELECTED_VENDORS_FILE)


class KEVScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Known Exploited Vulnerabilities Scanner")
        self.root.minsize(1000, 600)

        self.all_vendors = []
        self.all_vulnerabilities = []
        self.new_vuln_ids = set()
        self.selected_vendors = set(load_selected_vendors())
        self._after_id = None

        self._build_ui()
        self._load_initial_data()

    def _build_ui(self):
        # --- Left frame: vendor search + listbox ---
        frame_left = tk.Frame(self.root)
        frame_left.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)

        tk.Label(frame_left, text="Search Vendor").pack()

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)
        tk.Entry(frame_left, textvariable=self.search_var).pack(fill=tk.X)

        tk.Label(frame_left, text="Select Vendors").pack(pady=(8, 0))

        listbox_frame = tk.Frame(frame_left)
        listbox_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        lb_scroll = Scrollbar(listbox_frame, orient=tk.VERTICAL)
        self.listbox = Listbox(listbox_frame, selectmode=MULTIPLE, yscrollcommand=lb_scroll.set)
        lb_scroll.config(command=self.listbox.yview)
        lb_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        sel_btn_frame = tk.Frame(frame_left)
        sel_btn_frame.pack(fill=tk.X, pady=(2, 0))
        tk.Button(sel_btn_frame, text="Select All", command=self._select_all).pack(side=tk.LEFT, expand=True, fill=tk.X)
        tk.Button(sel_btn_frame, text="Deselect All", command=self._deselect_all).pack(side=tk.LEFT, expand=True, fill=tk.X)

        self.show_button = tk.Button(frame_left, text="Show Vulnerabilities", command=self._show_vulnerabilities)
        self.show_button.pack(pady=(8, 2), fill=tk.X)

        self.refresh_button = tk.Button(frame_left, text="Refresh Data", command=self._trigger_refresh)
        self.refresh_button.pack(fill=tk.X)

        # --- Right frame: results text box ---
        frame_right = tk.Frame(self.root)
        frame_right.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.BOTH, expand=True)

        text_frame = tk.Frame(frame_right)
        text_frame.pack(fill=tk.BOTH, expand=True)

        txt_scroll = Scrollbar(text_frame, orient=tk.VERTICAL)
        self.text_box = tk.Text(
            text_frame, wrap=tk.WORD, state=tk.DISABLED, yscrollcommand=txt_scroll.set
        )
        txt_scroll.config(command=self.text_box.yview)
        txt_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.text_box.tag_config("new_header", background="#ffe0e0", foreground="#990000", font=("TkDefaultFont", 9, "bold"))
        self.text_box.tag_config("new_body", background="#fff5f5")
        self.text_box.tag_config("link", foreground="blue", underline=True)
        self.text_box.tag_bind("link", "<Enter>", lambda e: self.text_box.config(cursor="hand2"))
        self.text_box.tag_bind("link", "<Leave>", lambda e: self.text_box.config(cursor=""))
        self.text_box.tag_bind("link", "<Button-1>", self._open_link)

        # --- Status bar ---
        self.status_var = tk.StringVar(value="Starting…")
        tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W).pack(
            side=tk.BOTTOM, fill=tk.X
        )

    def _set_status(self, msg):
        self.status_var.set(msg)
        self.root.update_idletasks()

    def _set_buttons_enabled(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        self.show_button.config(state=state)
        self.refresh_button.config(state=state)

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_initial_data(self):
        cached = load_data_from_file(LOCAL_JSON_FILE)
        if cached:
            self.all_vulnerabilities = cached
            self._refresh_vendor_list()
            self._set_status(f"Loaded {len(cached)} cached vulnerabilities. Fetching updates…")
        self._trigger_refresh()

    def _trigger_refresh(self):
        self._set_buttons_enabled(False)
        self._set_status("Fetching latest data from CISA…")
        threading.Thread(target=self._fetch_worker, daemon=True).start()

    def _fetch_worker(self):
        try:
            current = fetch_vulnerabilities()
        except Exception as exc:
            self.root.after(0, self._on_fetch_error, str(exc))
            return
        self.root.after(0, self._on_fetch_success, current)

    def _on_fetch_error(self, msg):
        self._set_buttons_enabled(True)
        self._set_status(f"Error fetching data: {msg}")
        if not self.all_vulnerabilities:
            messagebox.showerror("Network Error", f"Could not fetch vulnerability data:\n{msg}")
        self._schedule_auto_refresh()

    def _on_fetch_success(self, current):
        # Load the previous snapshot BEFORE overwriting the local file
        previous = load_data_from_file(PREVIOUS_JSON_FILE)
        new_vulns = compare_vulnerabilities(current, previous)
        self.new_vuln_ids = {v["cveID"] for v in new_vulns}

        # Rotate: copy current local file → previous, then save fresh data
        if os.path.exists(LOCAL_JSON_FILE):
            shutil.copy2(LOCAL_JSON_FILE, PREVIOUS_JSON_FILE)
        save_data_to_file(current, LOCAL_JSON_FILE)

        self.all_vulnerabilities = current
        self._refresh_vendor_list()

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = f"Updated {now} — {len(current)} total vulnerabilities"
        if new_vulns:
            status += f", {len(new_vulns)} NEW (highlighted in red)"
            messagebox.showinfo(
                "New Vulnerabilities",
                f"{len(new_vulns)} new vulnerabilities have been added since the last scan.",
            )
        self._set_status(status)
        self._set_buttons_enabled(True)
        self._schedule_auto_refresh()

    def _schedule_auto_refresh(self):
        if self._after_id is not None:
            self.root.after_cancel(self._after_id)
        self._after_id = self.root.after(AUTO_REFRESH_MS, self._trigger_refresh)

    # ------------------------------------------------------------------
    # Vendor listbox helpers
    # ------------------------------------------------------------------

    def _refresh_vendor_list(self):
        self.all_vendors = sorted(set(v["vendorProject"] for v in self.all_vulnerabilities))
        self._update_vendors_listbox(self.all_vendors)

    def _update_vendors_listbox(self, vendors):
        self.listbox.delete(0, END)
        for vendor in vendors:
            self.listbox.insert(END, vendor)
            if vendor in self.selected_vendors:
                self.listbox.select_set(END)

    def _on_search_change(self, *_):
        term = self.search_var.get().lower()
        filtered = [v for v in self.all_vendors if term in v.lower()]
        self._update_vendors_listbox(filtered)

    def _select_all(self):
        self.listbox.select_set(0, END)

    def _deselect_all(self):
        self.listbox.select_clear(0, END)

    # ------------------------------------------------------------------
    # Show vulnerabilities
    # ------------------------------------------------------------------

    def _show_vulnerabilities(self):
        indices = self.listbox.curselection()
        vendors = [self.listbox.get(i) for i in indices]
        self.selected_vendors = set(vendors)
        save_selected_vendors(vendors)

        filtered = [v for v in self.all_vulnerabilities if v["vendorProject"] in self.selected_vendors]
        filtered.sort(key=lambda x: x["dateAdded"], reverse=True)

        self.text_box.config(state=tk.NORMAL)
        self.text_box.delete(1.0, tk.END)

        for vuln in filtered:
            is_new = vuln["cveID"] in self.new_vuln_ids
            header_tag = "new_header" if is_new else ""
            body_tag = "new_body" if is_new else ""

            cve_id = vuln["cveID"]
            nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            prefix = "🆕 NEW  " if is_new else ""

            self.text_box.insert(tk.END, f'{prefix}CVE ID: {cve_id}\n', header_tag)
            self.text_box.insert(tk.END, f'Vendor: {vuln["vendorProject"]}\n', body_tag)
            self.text_box.insert(tk.END, f'Product: {vuln["product"]}\n', body_tag)
            self.text_box.insert(tk.END, f'Vulnerability Name: {vuln["vulnerabilityName"]}\n', body_tag)
            self.text_box.insert(tk.END, f'Date Added: {vuln["dateAdded"]}\n', body_tag)
            self.text_box.insert(tk.END, f'Due Date: {vuln.get("dueDate", "N/A")}\n', body_tag)
            self.text_box.insert(tk.END, f'Ransomware Use: {vuln.get("knownRansomwareCampaignUse", "Unknown")}\n', body_tag)
            self.text_box.insert(tk.END, f'Description: {vuln["shortDescription"]}\n', body_tag)
            self.text_box.insert(tk.END, f'Required Action: {vuln.get("requiredAction", "N/A")}\n', body_tag)
            self.text_box.insert(tk.END, "NVD Detail: ", body_tag)
            self.text_box.insert(tk.END, nvd_url, "link")
            self.text_box.insert(tk.END, "\n" + "-" * 60 + "\n", body_tag)

        if not filtered:
            self.text_box.insert(tk.END, "No vulnerabilities found for the selected vendors.\n")

        self.text_box.config(state=tk.DISABLED)

    def _open_link(self, event):
        idx = self.text_box.index(f"@{event.x},{event.y}")
        ranges = self.text_box.tag_ranges("link")
        for i in range(0, len(ranges) - 1, 2):
            start, end = ranges[i], ranges[i + 1]
            if self.text_box.compare(start, "<=", idx) and self.text_box.compare(idx, "<=", end):
                webbrowser.open(self.text_box.get(start, end))
                break


if __name__ == "__main__":
    root = tk.Tk()
    app = KEVScannerApp(root)
    root.mainloop()
