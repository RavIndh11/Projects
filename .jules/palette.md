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
## 2023-10-25 - Form Submission Loading State and A11y

**Learning:** When modifying forms, especially those that trigger long-running analysis tasks, it's critical to add immediate visual feedback (like a loading spinner and disabled state on the submit button). This prevents duplicate submissions and reduces user anxiety. Additionally, explicit indicators like red asterisks must be paired with `aria-required="true"` on the input element to ensure both visual and screen reader users understand the field is mandatory.
**Action:** Next time I modify a form, I will ensure it has a robust loading state and that all required fields are clearly marked visually and semantically.
## 2024-10-24 - Missing accessibility for icon-only utility buttons
**Learning:** Icon-only utility buttons (e.g. reload, refresh) often lack `aria-label`s and proper keyboard focus visible styles when they use icons directly (e.g. FontAwesome). Users navigating via screen readers or keyboards are unable to interact with them effectively.
**Action:** When reviewing UI dashboards, always look for utility actions disguised as icons and explicitly verify `aria-label` attributes and `:focus-visible` / `focus:ring` classes exist.
