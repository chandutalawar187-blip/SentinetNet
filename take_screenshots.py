import asyncio
from playwright.async_api import async_playwright
import os

async def main():
    print("Starting playwright...")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1920, "height": 1080})
        
        print("Navigating to http://localhost:5000...")
        await page.goto("http://localhost:5000")
        # Wait for Streamlit to render completely
        await page.wait_for_timeout(5000)
        
        os.makedirs("screenshots", exist_ok=True)
        
        print("Taking screenshots...")
        # Since it's a single page Streamlit app, we will take a full page screenshot
        # and save it for the required filenames as per README.
        await page.screenshot(path="screenshots/dashboard.png", full_page=True)
        
        # Scroll to bottom to capture history and alerts
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await page.wait_for_timeout(1000)
        await page.screenshot(path="screenshots/alerts.png")
        
        # Scroll to middle for active threat
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
        await page.wait_for_timeout(1000)
        await page.screenshot(path="screenshots/detection-example.png")
        
        print("Screenshots saved successfully.")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
