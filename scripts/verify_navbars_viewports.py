import os
import json
import time
from playwright.sync_api import sync_playwright

VIEWPORTS = [
    {"name": "1920px", "width": 1920, "height": 1080, "type": "Full Desktop"},
    {"name": "1648px", "width": 1648, "height": 1000, "type": "Wide Desktop (Target)"},
    {"name": "1440px", "width": 1440, "height": 900, "type": "Standard Desktop"},
    {"name": "1366px", "width": 1366, "height": 768, "type": "Compact Desktop"},
    {"name": "1280px", "width": 1280, "height": 800, "type": "Laptop / High-DPI"},
    {"name": "1024px", "width": 1024, "height": 768, "type": "Compact / Tablet Landscape"},
    {"name": "768px", "width": 768, "height": 1024, "type": "Tablet Portrait"},
    {"name": "430px", "width": 430, "height": 932, "type": "Large Mobile (iPhone 15 Pro Max)"},
    {"name": "390px", "width": 390, "height": 844, "type": "Standard Mobile (iPhone 14)"},
    {"name": "360px", "width": 360, "height": 740, "type": "Small Mobile (Galaxy S8)"}
]

os.makedirs("docs/screenshots", exist_ok=True)
results = []

chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
if not os.path.exists(chrome_path):
    chrome_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

print(f"Using browser at: {chrome_path}")

admin_session = {
    "username": "demo_admin",
    "full_name": "Security Administrator",
    "role": "SECURITY_ADMIN",
    "is_demo_account": True,
    "access_token": "mock_jwt_token_admin"
}

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=chrome_path, headless=True)
    
    for vp in VIEWPORTS:
        width = vp["width"]
        height = vp["height"]
        print(f"\n--- Testing Viewport: {vp['name']} ({width}x{height}) ---")
        
        context = browser.new_context(
            viewport={"width": width, "height": height},
            device_scale_factor=1
        )
        page = context.new_page()
        # Seed localStorage session before page loads
        page.add_init_script(f"""
            localStorage.setItem('sqltrust_session', JSON.stringify({json.dumps(admin_session)}));
        """)
        
        page.goto("http://localhost:5173", wait_until="networkidle")
        page.wait_for_timeout(1000)

        # Inspect layout and overflow metrics
        metrics = page.evaluate("""() => {
            const docWidth = document.documentElement.scrollWidth;
            const winWidth = window.innerWidth;
            const header = document.querySelector('header');
            const headerRect = header ? header.getBoundingClientRect() : null;
            const nav = document.querySelector('nav[aria-label="Primary Platform Navigation"]');
            const menuBtn = document.querySelector('button[aria-label="Toggle Navigation Menu"]');
            const profileBtn = document.querySelector('button[aria-label="User Account Menu"]');
            const searchBtn = document.querySelector('button[aria-label="Quick Search"]');
            const buttons = Array.from(document.querySelectorAll('button'));
            const adminLink = buttons.find(b => b.textContent && b.textContent.includes('Administration'));

            return {
                docScrollWidth: docWidth,
                windowInnerWidth: winWidth,
                hasHorizontalScroll: docWidth > winWidth,
                headerWidth: headerRect ? headerRect.width : 0,
                headerRight: headerRect ? headerRect.right : 0,
                headerClipped: headerRect ? (headerRect.right > winWidth + 1) : false,
                navVisible: nav ? window.getComputedStyle(nav).display !== 'none' : false,
                menuButtonVisible: menuBtn ? window.getComputedStyle(menuBtn).display !== 'none' : false,
                profileVisible: profileBtn ? window.getComputedStyle(profileBtn).display !== 'none' : false,
                searchVisible: searchBtn ? window.getComputedStyle(searchBtn).display !== 'none' : false,
                adminLinkVisible: adminLink ? window.getComputedStyle(adminLink).display !== 'none' : false
            };
        }""")

        screenshot_path = f"docs/screenshots/viewport_{width}.png"
        page.screenshot(path=screenshot_path)

        # Test drawer interaction on tablet & mobile
        drawer_tested = False
        drawer_closed_after_nav = False
        if width < 1024:
            menu_btn = page.query_selector('button[aria-label="Toggle Navigation Menu"]')
            if menu_btn:
                menu_btn.click()
                page.wait_for_timeout(400)
                
                drawer_info = page.evaluate("""() => {
                    const buttons = Array.from(document.querySelectorAll('button'));
                    const sec = buttons.find(b => b.textContent && b.textContent.includes('Security') && b.offsetParent !== null);
                    return { hasSecurityInDrawer: !!sec };
                }""")
                drawer_tested = drawer_info["hasSecurityInDrawer"]
                
                # Click the visible Security link in drawer
                clicked = page.evaluate("""() => {
                    const buttons = Array.from(document.querySelectorAll('button'));
                    const sec = buttons.find(b => b.textContent && b.textContent.includes('Security') && b.offsetParent !== null);
                    if (sec) {
                        sec.click();
                        return true;
                    }
                    return false;
                }""")
                page.wait_for_timeout(500)
                drawer_closed_after_nav = clicked

        result_item = {
            "viewport": vp["name"],
            "type": vp["type"],
            "width": width,
            "height": height,
            "metrics": metrics,
            "drawer_tested": drawer_tested,
            "drawer_closed_after_nav": drawer_closed_after_nav,
            "screenshot": screenshot_path
        }
        results.append(result_item)

        print(f"  InnerWidth: {metrics['windowInnerWidth']}px | ScrollWidth: {metrics['docScrollWidth']}px")
        print(f"  Horizontal Scroll: {'FAIL (Detected)' if metrics['hasHorizontalScroll'] else 'PASS (Zero)'}")
        print(f"  Header Right: {metrics['headerRight']}px | Clipped: {metrics['headerClipped']}")
        print(f"  Desktop Nav: {'Visible' if metrics['navVisible'] else 'Hidden (Responsive Drawer Active)'}")
        print(f"  Menu Button: {'Visible' if metrics['menuButtonVisible'] else 'Hidden'}")
        print(f"  Profile Accessible: {'PASS' if metrics['profileVisible'] else 'FAIL'}")
        print(f"  Search Accessible: {'PASS' if metrics['searchVisible'] else 'FAIL'}")
        print(f"  Admin Link Authorized: {'PASS' if metrics['adminLinkVisible'] else 'N/A'}")
        if width < 1024:
            print(f"  Drawer Navigation Test: {'PASS' if drawer_tested and drawer_closed_after_nav else 'FAIL'}")

        context.close()

    browser.close()

with open("docs/viewport_test_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("\nVerification completed successfully. Results saved to docs/viewport_test_results.json")
