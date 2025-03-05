import undetected_chromedriver as uc

def fetch_content(url):
    """Fetch webpage content using Selenium."""
    print(f"Fetching content from: {url}")

    # Use undetected_chromedriver to avoid version mismatch
    options = uc.ChromeOptions()
    options.add_argument("--headless")  # Headless mode (no GUI)
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    driver = uc.Chrome(options=options)  # Auto-downloads the right driver

    try:
        driver.get(url)
        driver.implicitly_wait(5)  # Wait for JavaScript to load

        content = driver.page_source
        return {"content": content}

    except Exception as e:
        return {"error": f"Failed to fetch content: {str(e)}"}

    finally:
        driver.quit()
