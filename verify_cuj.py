from playwright.sync_api import sync_playwright

def run_cuj(page):
    page.goto("http://localhost:8000")
    page.wait_for_timeout(500)

    # Fill in a URL
    page.get_by_role("textbox", name="Enter URL to Fetch:").fill("http://example.com")
    page.wait_for_timeout(500)

    # Setup network interception to delay the request and allow for capturing the "loading" state
    page.route("**/api/fetch", lambda route: (
        page.wait_for_timeout(2000),
        route.continue_()
    ))

    # Click submit
    page.get_by_role("button", name="Safely Fetch URL").click()
    page.wait_for_timeout(500)

    # Take screenshot while fetching
    page.screenshot(path="/home/jules/verification/screenshots/verification.png")
    page.wait_for_timeout(2500) # Hold for video and let network complete

if __name__ == "__main__":
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            record_video_dir="/home/jules/verification/videos"
        )
        page = context.new_page()
        try:
            run_cuj(page)
        finally:
            context.close()
            browser.close()
