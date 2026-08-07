# SAMATI beta security

The production server validates Google sessions, restricts cross-origin writes, rate-limits API calls, sanitizes realtime presence, and records suspicious economy changes.

Focus rewards are server-timed and single-use. The client starts a signed-in focus session through `/api/focus/start`; `/api/focus/complete` calculates the credited duration and coin reward from server time. Reusing a focus token is rejected.

Cloud saves are normalized on the server. Abnormal coin increases are rejected and recorded in `security_events`. The authoritative value is returned to the client and replaces the local value.

Administrative access is granted only when the authenticated Google email is present in the `ADMIN_EMAILS` Render environment variable. Client-side email claims do not grant server permissions.

This is beta protection, not a complete commercial economy. Before enabling real-money purchases, inventory ownership, shop transactions, drops, and sales must also become server-authoritative and payment fulfillment must use verified provider webhooks.
