# Subscriber Escalation Recon — Field Notes

From wines.com deep invasion (June 2026). WordPress 6.3.1, subdirectory installation at /magical/, GoDaddy shared hosting.

## What Worked as Subscriber

| Action | Method | Result |
|--------|--------|--------|
| Register account | POST /wp-login.php?action=register | Account created |
| Reset password via Mailinator | Mailinator API → extract rp_key → GET reset page → POST new password | Password set, XMLRPC auth works |
| XMLRPC auth check | wp.getUsersBlogs | blogid=1 confirmed, subscriber role |
| wp.getProfile | XMLRPC | ID=18220, roles=["subscriber"] |
| wp.getOptions | XMLRPC | 29-116 options returned (blog metadata only) |
| wp.getPost | XMLRPC | 401 not allowed for subscriber |

## What BLOCKED Subscriber-Level Escalation

| Vector | Error | Why |
|--------|-------|-----|
| wp.uploadFile | faultCode 401 "not allowed to upload files" | Capability check blocks subscriber |
| metaWeblog.newMediaObject | faultCode 401 | Same capability check |
| Application Passwords REST | rest_cookie_invalid_nonce | Nonce rendered in DOM but subscriber POST fails |
| ElementsKit admin-ajax | 0 response | Nonce not extractable from subscriber profile page |
| wp.editProfile role change | Returns true but role unchanged | Role field silently ignored for subscriber |
| REST /wp/v2/users/me | rest_not_logged_in | Cookie auth fails for subdirectory installs |

## Subscriber Enumeration — What wp.getOptions Actually Returns

The XMLRPC `wp.getOptions` method (blogid, user, pass params) returns ~29 non-empty values. ALL are blog-level metadata:

- template: rigel
- blog_title: Wines.com
- date_format: F j, Y
- time_format: g:i a
- software_version: 6.3.1
- blog_url, home_url, login_url, admin_url (URLs)
- default_comment_status: closed
- default_ping_status: open

**No sensitive values ever returned:** admin_email is empty, SMTP/server/API options not exposed, password/key fields empty. The method gives subscriber-level blog metadata only.

## Cookie Auth Issues with Subdirectory WordPress

WordPress installed in `/magical/` sets cookies with path restriction:
- wordpress_sec_* → Path=/magical/wp-admin
- wordpress_logged_in_* → Path=/magical/wp-content/plugins (variable)

When using curl with cookie jar (-c/-b), the root site REST API (/wp-json/) goes through the main WordPress install which has no session. The /magical/ REST API is not exposed separately. **All authenticated actions must go through XMLRPC**, not the REST API or wp-admin web interface.

## Key Lessons

1. If wp.editProfile returns true but doesn't change role, use wp.getProfile to verify — never trust the boolean return.
2. Application Passwords REST endpoint responds even to unauthenticated requests, but session cookies from subdirectory installs rarely work with curl for REST auth.
3. system.multicall is the fastest brute force path (100+ passwords/request). Targeted wordlists (company name + year + specials) work better than generic rockyou when rockyou isn't available.
4. Confirm blog_id with wp.getUsersBlogs BEFORE trying wp.getOptions — the blog_id defaults to 1 but some multisite setups use different ids.
5. Always check both /wp-json/wp/v2/users (main) AND /magical/wp-json/wp/v2/users (subdirectory) — they may have DIFFERENT user sets.
