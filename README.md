# Known Exploited Vulnerabilities Scanner (KEVS)

This Python application scans CISA's Known Exploited Vulnerabilities (KEV) catalogue and displays vulnerabilities filtered by vendor. It highlights entries that are new since the previous scan and automatically refreshes the data every hour.

## Features

- Fetches the latest KEV data from CISA on startup and every hour.
- Displays a scrollable list of unique vendors.
- Real-time vendor search/filter.
- Select All / Deselect All vendor controls.
- Displays vulnerabilities for selected vendors sorted by date (newest first).
- **Highlights new vulnerabilities** (added since the last scan) in red.
- Shows all relevant fields: CVE ID, vendor, product, name, date added, due date, required action, ransomware use, and description.
- Clickable NVD links open the full CVE detail page in your browser.
- Status bar shows the last update time and new vulnerability count.
- Saves and restores selected vendors between sessions.
- Background fetch keeps the UI responsive at all times.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/RootThePlanet/KEVScanner.git
   cd KEVScanner
   ```

2. **Create and Activate a Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

> **Note:** `tkinter` is part of Python's standard library and does not need to be installed via pip. On some Linux distributions you may need to install the `python3-tk` system package (e.g. `sudo apt install python3-tk`).

## Usage

1. **Run the Application:**
   ```bash
   python main.py
   ```

2. **Interact with the GUI:**
   - Type in the **Search Vendor** box to filter the vendor list in real time.
   - Select one or more vendors in the listbox (use **Select All** / **Deselect All** as needed).
   - Click **Show Vulnerabilities** to display matching CVEs in the right panel.
   - New vulnerabilities (added since the last scan) are highlighted in red with a 🆕 prefix.
   - Click any **NVD Detail** link to open the full CVE record in your browser.
   - Click **Refresh Data** to manually fetch the latest KEV catalogue.
   - The status bar at the bottom shows the last update time and how many new CVEs were found.

## File Structure

- `main.py` — Main application script.
- `requirements.txt` — Python dependencies (`requests`).
- `vulnerabilities.json` — Latest KEV data cached locally.
- `previous_vulnerabilities.json` — Previous snapshot used to detect new entries.
- `selected_vendors.json` — Persisted vendor selections.

## How It Works

1. **Startup** — Any previously cached data is loaded immediately so the UI is usable offline.
2. **Fetch** — The latest KEV JSON is fetched from CISA in a background thread.
3. **Compare** — The fresh data is compared against the previous snapshot (`previous_vulnerabilities.json`) to identify new CVEs.
4. **Rotate** — The current local file becomes the new previous snapshot; the fresh data is saved as the current file.
5. **Display** — Vendors are updated in the listbox; new CVE IDs are tracked for highlighting when results are shown.
6. **Auto-refresh** — Steps 2–5 repeat automatically every hour.

## Potential Enhancements

- Additional filtering options (by product, date range, severity).
- Export results to CSV or PDF.
- Desktop notifications for new vulnerabilities.
- Integration with additional threat-intelligence sources.

## Contributions

Contributions are welcome! Feel free to submit a pull request or open an issue to discuss changes.

## Acknowledgments

- [CISA](https://www.cisa.gov) for providing the KEV catalogue.
- The [Tkinter](https://docs.python.org/3/library/tkinter.html) library for the GUI framework.

