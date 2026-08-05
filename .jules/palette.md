## 2025-02-28 - Dynamic Content Announcement in Single Page Applications
**Learning:** When results or status messages appear dynamically on a page without a reload (like a `fetch` response), screen readers will not announce them by default. Using `aria-live="polite"` on the container (e.g., the results section) is critical so users relying on assistive technologies are notified when the content updates.
**Action:** Always ensure containers for asynchronously loaded content (like search results, form submission feedback, or threat analysis results) use an appropriate `aria-live` attribute.

## 2025-02-28 - Explicit Labeling and Synchronous Form Feedback
**Learning:** Screen readers may not inherently associate a heading (like `<h2>`) with an adjacent input field without explicit linkage, and synchronous file uploads lack native feedback during submission, leading to poor UX and potential double submissions.
**Action:** Always wrap instructional headings in a `<label for="...">` tied to the input's `id`, and implement immediate visual feedback (e.g., loading spinner, disabled state) via an `onsubmit` handler for synchronous form submissions.
## 2024-05-14 - Visual loading states on auto-refreshing UI
**Learning:** When combining manual user actions (like a "Refresh" button) with background auto-polling in a dashboard, visual loading states (like spinners and disabled buttons) should only be triggered by the manual action. Triggering them on the auto-polling interval creates an annoying and distracting UI flicker.
**Action:** Always check if a dashboard has a `setInterval` for fetching data before adding loading states. Pass an `isManual` flag from the button's event handler to the fetch function to selectively apply the loading UI only when the user explicitly interacts with it.
