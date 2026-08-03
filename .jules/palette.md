## 2025-02-28 - Dynamic Content Announcement in Single Page Applications
**Learning:** When results or status messages appear dynamically on a page without a reload (like a `fetch` response), screen readers will not announce them by default. Using `aria-live="polite"` on the container (e.g., the results section) is critical so users relying on assistive technologies are notified when the content updates.
**Action:** Always ensure containers for asynchronously loaded content (like search results, form submission feedback, or threat analysis results) use an appropriate `aria-live` attribute.
