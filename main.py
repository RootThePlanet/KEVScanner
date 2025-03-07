import json
import requests
import os
import tkinter as tk
from tkinter import messagebox, Listbox, MULTIPLE, END

json_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
local_json_file = "vulnerabilities.json"
selected_vendors_file = "selected_vendors.json"

def fetch_and_save_vulnerabilities():
    response = requests.get(json_url)
    vulnerabilities = response.json()["vulnerabilities"]
    with open(local_json_file, "w") as file:
        json.dump(vulnerabilities, file, indent=4)
    return vulnerabilities

def load_data_from_file(filename):
    if not os.path.exists(filename):
        return {}
    with open(filename, "r") as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return {}

def save_data_to_file(data, filename):
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

def compare_vulnerabilities(current, previous):
    current_set = set((item["cveID"], item["dateAdded"]) for item in current)
    previous_set = set((item["cveID"], item["dateAdded"]) for item in previous)
    new_vulnerabilities = current_set - previous_set
    return [item for item in current if (item["cveID"], item["dateAdded"]) in new_vulnerabilities]

def load_selected_vendors():
    selected_vendors = load_data_from_file(selected_vendors_file)
    return selected_vendors.get("vendors", [])

def save_selected_vendors(vendors):
    save_data_to_file({"vendors": vendors}, selected_vendors_file)

def update_vendors_listbox(vendors, selected_vendors):
    listbox.delete(0, END)
    for vendor in sorted(vendors):
        listbox.insert(END, vendor)
        if vendor in selected_vendors:
            listbox.select_set(END)

def show_vulnerabilities():
    selected_indices = listbox.curselection()
    selected_vendors = [listbox.get(i) for i in selected_indices]
    selected_vendors_var.set(", ".join(selected_vendors))
    save_selected_vendors(selected_vendors)
    
    vulnerabilities = fetch_and_save_vulnerabilities()
    filtered_vulnerabilities = [vuln for vuln in vulnerabilities if vuln["vendorProject"] in selected_vendors]
    filtered_vulnerabilities.sort(key=lambda x: x["dateAdded"], reverse=True)
    
    text_box.config(state=tk.NORMAL)
    text_box.delete(1.0, tk.END)
    
    for vuln in filtered_vulnerabilities:
        text_box.insert(tk.END, f'CVE ID: {vuln["cveID"]}\n')
        text_box.insert(tk.END, f'Product: {vuln["product"]}\n')
        text_box.insert(tk.END, f'Vulnerability Name: {vuln["vulnerabilityName"]}\n')
        text_box.insert(tk.END, f'Date Added: {vuln["dateAdded"]}\n')
        text_box.insert(tk.END, f'Short Description: {vuln["shortDescription"]}\n')
        text_box.insert(tk.END, f'CVSS Score: https://nvd.nist.gov/vuln/detail/{vuln["cveID"]}\n')
        text_box.insert(tk.END, '-'*40 + '\n')
    
    text_box.config(state=tk.DISABLED)

# Fetch and save initial data
vulnerabilities = fetch_and_save_vulnerabilities()
previous_vulnerabilities = load_data_from_file(local_json_file)
new_vulnerabilities = compare_vulnerabilities(vulnerabilities, previous_vulnerabilities)

save_data_to_file(vulnerabilities, local_json_file)

# Initialize GUI
root = tk.Tk()
root.title("Known Exploited Vulnerabilities Scanner")

frame_left = tk.Frame(root)
frame_left.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)

frame_middle = tk.Frame(root)
frame_middle.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)

frame_right = tk.Frame(root)
frame_right.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.BOTH, expand=True)

search_label = tk.Label(frame_left, text="Search Vendor")
search_label.pack()

search_entry = tk.Entry(frame_left)
search_entry.pack()

listbox_label = tk.Label(frame_left, text="Select Vendors")
listbox_label.pack()

listbox = Listbox(frame_left, selectmode=MULTIPLE)
listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

selected_vendors_var = tk.StringVar()
selected_vendors_label = tk.Label(frame_middle, text="Selected Vendors")
selected_vendors_label.pack()

selected_vendors_box = tk.Label(frame_middle, textvariable=selected_vendors_var, justify=tk.LEFT)
selected_vendors_box.pack(padx=10, pady=10)

show_button = tk.Button(frame_left, text="Show Vulnerabilities", command=show_vulnerabilities)
show_button.pack()

text_box = tk.Text(frame_right, wrap=tk.WORD, state=tk.DISABLED)
text_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

def search_vendors(event):
    search_term = search_entry.get().lower()
    filtered_vendors = [vendor for vendor in all_vendors if search_term in vendor.lower()]
    update_vendors_listbox(filtered_vendors, selected_vendors)

search_entry.bind("<KeyRelease>", search_vendors)

all_vendors = sorted(set(vuln["vendorProject"] for vuln in vulnerabilities))
selected_vendors = set(load_selected_vendors())

update_vendors_listbox(all_vendors, selected_vendors)

root.mainloop()
