import pandas as pd
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from concurrent.futures import ThreadPoolExecutor
import threading

# Thread-local storage to maintain one driver per thread
thread_local = threading.local()

def get_driver():
    if not hasattr(thread_local, "driver"):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        service = Service(ChromeDriverManager().install())
        thread_local.driver = webdriver.Chrome(service=service, options=chrome_options)
    return thread_local.driver

def scrape_cvss_vector(cve_id):
    driver = get_driver()
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    try:
        # Open the given URL
        driver.get(url)
        print(f"Page opened successfully for {cve_id}.")

        # Wait for the CVSS 3.1 button to be clickable and click it
        try:
            wait = WebDriverWait(driver, 20)
            cvss_button = wait.until(EC.element_to_be_clickable((By.XPATH, "//*[@id='btn-cvss3']")))
            cvss_button.click()
            print(f"Clicked on CVSS 3.1 button for {cve_id} successfully.")
        except Exception:
            # If the button is not available, return None
            print(f"CVSS 3.1 button not available for {cve_id}. Skipping.")
            return cve_id, None

        # Wait explicitly until the Vector element is present under the CVSS panel
        try:
            vector_element = wait.until(
                EC.presence_of_element_located((By.XPATH, "//*[@id='Vuln3CvssPanel']/div/div[3]"))
            )
            # Extract and return the Vector text
            cvss_vector = vector_element.text
            print(f"CVSS Vector for {cve_id}: {cvss_vector}")
            return cve_id, cvss_vector

        except Exception:
            # Handle the case where the vector element is not found
            print(f"CVSS Vector not available for {cve_id}. Skipping.")
            return cve_id, None

    except Exception as e:
        # Handle cases where the page could not be loaded
        print(f"An error occurred for {cve_id}: {e}. Skipping.")
        return cve_id, None

def process_cve_file(input_file):
    # Load the Excel file into a DataFrame
    df = pd.read_excel(input_file, engine='openpyxl')
    
    # Assuming CVE IDs are in Column A
    cve_ids = df['CVE ID']  # Replace with the appropriate column name if different

    # Use ThreadPoolExecutor for multithreading
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(scrape_cvss_vector, cve_ids))

    # Update the DataFrame with the results
    for cve_id, vector in results:
        df.loc[df['CVE ID'] == cve_id, 'CVSS Vector'] = vector

    # Save the updated DataFrame to the same Excel file
    df.to_excel(input_file, index=False, engine='openpyxl')

# File path
input_file = 'cve_list_attack_vector_py.xlsx'  # Input Excel file with CVE IDs in Column A

# Process the CVE file
process_cve_file(input_file)
