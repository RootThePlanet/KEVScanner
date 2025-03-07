# Known Exploited Vulnerabilities Scanner (KEVS)

This Python application scans a hosted JSON file from CISA to identify known exploited vulnerabilities. It allows users to select vendors from a picklist, view vulnerabilities related to the selected vendors, and highlight new vulnerabilities added since the last scan.

## Features

- Fetches vulnerability data from CISA's hosted JSON file.
- Displays a list of unique vendors.
- Allows users to select multiple vendors.
- Displays vulnerabilities related to the selected vendors.
- Highlights new vulnerabilities since the last scan.
- Provides detailed information for each vulnerability.
- Includes a link to the CVSS score for each vulnerability.
- Saves and loads selected vendors.
- Automatically refreshes the data every hour.

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/known-exploited-vulnerabilities-scanner.git
   cd known-exploited-vulnerabilities-scanner
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

## Usage

1. **Run the Application:**
   ```bash
   python main.py
   ```

2. **Interact with the GUI:**
   - Use the search box to filter vendors in the listbox.
   - Select multiple vendors from the listbox.
   - View vulnerabilities related to the selected vendors in the right panel.
   - Click "Click for more details" to view detailed information about the vulnerability.
   - Click "CVSS Score" to view the CVSS score of the vulnerability.

## File Structure

- `main.py`: Main application script.
- `requirements.txt`: List of dependencies.
- `previous_vulnerabilities.json`: File to save previous vulnerabilities for comparison.
- `selected_vendors.json`: File to save selected vendors.

## How It Works

1. **Fetching Data:**
   - The application fetches vulnerability data from the CISA URL.

2. **Comparing Data:**
   - The application compares the current data with the previously saved data to identify new vulnerabilities.

3. **Displaying Data:**
   - The application displays the vulnerabilities in the GUI, highlighting new ones.

4. **Saving and Loading Data:**
   - The application saves the selected vendors and previous vulnerabilities to JSON files and loads them on startup.

## Enhancements

Potential enhancements include:
- Adding more filtering options (e.g., by product, date).
- Integrating more data sources.
- Adding more detailed CVSS information.
- Implementing user authentication for saving preferences.

## Contributions

Contributions are welcome! Feel free to submit a pull request or open an issue to discuss changes.

## Acknowledgments

- [CISA](https://www.cisa.gov) for providing the vulnerability data.
- The [Tkinter](https://docs.python.org/3/library/tkinter.html) library for the GUI framework.

