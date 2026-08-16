## 2025-02-28 - Dynamic Content Announcement in Single Page Applications
**Learning:** When results or status messages appear dynamically on a page without a reload (like a `fetch` response), screen readers will not announce them by default. Using `aria-live="polite"` on the container (e.g., the results section) is critical so users relying on assistive technologies are notified when the content updates.
**Action:** Always ensure containers for asynchronously loaded content (like search results, form submission feedback, or threat analysis results) use an appropriate `aria-live` attribute.

## 2025-02-28 - Explicit Labeling and Synchronous Form Feedback
**Learning:** Screen readers may not inherently associate a heading (like `<h2>`) with an adjacent input field without explicit linkage, and synchronous file uploads lack native feedback during submission, leading to poor UX and potential double submissions.
**Action:** Always wrap instructional headings in a `<label for="...">` tied to the input's `id`, and implement immediate visual feedback (e.g., loading spinner, disabled state) via an `onsubmit` handler for synchronous form submissions.
## 2024-05-14 - Visual loading states on auto-refreshing UI
**Learning:** When combining manual user actions (like a "Refresh" button) with background auto-polling in a dashboard, visual loading states (like spinners and disabled buttons) should only be triggered by the manual action. Triggering them on the auto-polling interval creates an annoying and distracting UI flicker.
**Action:** Always check if a dashboard has a `setInterval` for fetching data before adding loading states. Pass an `isManual` flag from the button's event handler to the fetch function to selectively apply the loading UI only when the user explicitly interacts with it.

## 2024-05-14 - Accessible Inline Error Messages
**Learning:** Native `alert()` dialogs block the main thread, provide a jarring user experience, and are often poorly handled by screen readers. Furthermore, standard JavaScript `alert`s cannot be styled to match the application's design system.
**Action:** When handling asynchronous fetch errors (like API analysis failures), always use an inline, hidden `div` with `role="alert"` and visually display it (by removing the `hidden` class) when an error occurs. Ensure this container matches the app's styling and is easily dismissible or resetting on the next action.

## 2024-05-14 - Empty States and Loading Spinners on Synchronous Forms
**Learning:** Adding empty states to pages waiting for file uploads is critical to prevent the page from looking unfinished or blank. Furthermore, inline JavaScript `onsubmit` handlers are an effective way to disable submit buttons and show loading spinners for simple server-rendered forms without requiring an external JavaScript file.
**Action:** Always include empty states for sections depending on user data. For synchronous form submissions, use an `onsubmit` handler to disable the button and show a loading spinner to prevent double submissions and provide immediate feedback.
