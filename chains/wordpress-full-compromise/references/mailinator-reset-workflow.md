# Mailinator WordPress Password Reset Workflow

When WordPress has open registration, it sends a **reset LINK** to the user's email, not the password itself. This document covers the full Mailinator-based workflow to extract the reset key and set your own password.

## Prerequisites

- Open registration confirmed on target: `POST /wp-login.php?action=register`
- Mailinator inbox created with random prefix (e.g., `wineatk3083@mailinator.com`)
- [Optional] Python/requests library for parsing

## Step-by-Step

### 1. Register Account

```bash
USER="yourprefix$(date +%s)"
EMAIL="${USER}@mailinator.com"

curl -sk -X POST "https://TARGET/wp-login.php?action=register" \
  -d "user_login=${USER}&user_email=${EMAIL}&wp-submit=Register"
```

### 2. Wait and Check Mailinator Inbox

WordPress sends the email within 2-5 seconds. Use the Mailinator API v2:

```bash
# Check inbox
curl -sk "https://www.mailinator.com/api/v2/domains/public/inbox/${USER}" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for msg in d.get('messages', []):
    print(f\"ID: {msg.get('id')} | From: {msg.get('fromfull')} | Subj: {msg.get('subject')}\")
"
```

### 3. Extract Reset Key from Email

```bash
# Read the message body
MSG_DATA=$(curl -sk "https://www.mailinator.com/api/v2/message/${MSG_ID}")

# Extract the reset key from the URL in the email body
# WordPress format: wp-login.php?action=rp&key=XXXX&login=YYYY
RESET_KEY=$(echo "$MSG_DATA" | python3 -c "
import sys, re, html
data = sys.stdin.read()
# Find URL in the email body
url_match = re.search(r'wp-login\.php\?action=rp&amp;key=([a-zA-Z0-9]+)&amp;login=([^\"<\\s]+)', data)
if url_match:
    print(f\"{url_match.group(1)}:{url_match.group(2)}\")
else:
    # Try plain HTML entities
    url_match = re.search(r'wp-login\\.php\\?action=rp[^?]*?key=([a-zA-Z0-9]+)[^?]*?login=([^\"<\\s]+)', html.unescape(data))
    if url_match:
        print(f\"{url_match.group(1)}:{url_match.group(2)}\")
    else:
        print('KEY_NOT_FOUND')
")

RP_KEY=$(echo "$RESET_KEY" | cut -d: -f1)
RP_LOGIN=$(echo "$RESET_KEY" | cut -d: -f2)

echo "Reset Key: $RP_KEY"
echo "Login: $RP_LOGIN"
```

### 4. Execute Password Reset

WordPress requires TWO steps:

```bash
NEW_PASS="Hack123!@#"

# Step 4a: GET the reset page to obtain wp-resetpass-* cookie
curl -sk -c /tmp/wp_cookies.txt \
  "https://TARGET/wp-login.php?action=rp&key=${RP_KEY}&login=${RP_LOGIN}" \
  -o /dev/null

# Step 4b: POST the new password
curl -sk -b /tmp/wp_cookies.txt -X POST \
  "https://TARGET/wp-login.php?action=resetpass" \
  -d "rp_key=${RP_KEY}&rp_login=${RP_LOGIN}&pass1=${NEW_PASS}&pass2=${NEW_PASS}&wp-submit=Reset+Password"
```

### 5. Verify Authentication

```bash
# Confirm via XMLRPC (works even if cookie-based auth fails)
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d "<?xml version=\"1.0\"?>
<methodCall><methodName>wp.getUsersBlogs</methodName>
<params><param><value><string>${RP_LOGIN}</string></value></param>
<param><value><string>${NEW_PASS}</string></value></param></params></methodCall>"

# Expected: returns blogid, blogName — confirms auth works
```

## Pitfalls

- **Not all Mailinator domains work.** Mailinator has v1 (public inboxes) and v2 (private domains). The `/api/v2/domains/public/inbox/{user}` endpoint works for most public inboxes. For private domains, the endpoint is `/api/v2/domains/private/inbox/{user}` (requires token auth).
- **Reset page vs. API:** WordPress sends the email with FULL HTML body. The password is NOT in the email — only a link. The link contains `key=<hash>&login=<username>`.
- **Cookie `wp-resetpass-*`** is required for step 4b. If you skip step 4a (GET), step 4b returns `invalid_key`.
- **`rp_key` vs form field:** The HTML reset form might not auto-fill the `rp_key` field even when the URL contains it. Always pass it as a POST parameter explicitly.
- **Check the user ROLE immediately** after registration using `wp.getProfile`. Modern WordPress (6.x) registers as `subscriber` by default — which cannot upload files.
