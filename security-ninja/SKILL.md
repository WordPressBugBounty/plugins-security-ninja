---
name: security-ninja
description: >-
  Configure WP Security Ninja, read scan and audit results, and work through a
  harden checklist. Use when the user asks about Security Ninja, a firewall
  block, security tests, known vulnerabilities, core file changes, login
  protection, or hardening a WordPress site that has this plugin installed.
---

# Security Ninja

Instructions for an external coding agent (Cursor, Claude, and similar). This file ships in the plugin folder as `wp-content/plugins/security-ninja/SKILL.md`.

This is not the WordPress Abilities API. Abilities are read-only hooks for other AI tools on the same site. This skill is how an agent talks about the product and what it may change.

## Product truth

Free:

- 8G firewall
- 50+ security tests
- Vulnerability scanner (plugins, themes, WordPress core)
- Core scanner
- Basic events logger (firewall events and login attempts)
- AI Security Advisor on WordPress 7 (monthly automatic review)

Pro adds:

- Cloud firewall, country blocking, 404 Guard, visitor logging
- Malware scanner
- Login protection, rename login, two-factor authentication
- Fixes page (one-click hardening)
- Full events logger (export, webhooks, scheduled reports)
- Scheduled scans
- White label
- WooCommerce and SureCart store protection

Do not tell a free site to turn on a Pro-only control. Point them at the upgrade instead.

White label (Pro) can rename the menu. Look for the plugin files and the `page=wf-sn` admin URL, not only the words "Security Ninja".

## Where to work

WordPress admin, user who can `manage_options`:

| Area | URL |
|---|---|
| Overview | `admin.php?page=wf-sn#sn_overview` |
| Security tests | `admin.php?page=wf-sn#sn_tests` |
| Vulnerabilities | `admin.php?page=wf-sn#sn_vuln` |
| Core scanner | `admin.php?page=wf-sn#sn_core` |
| Firewall | `admin.php?page=wf-sn#sn_cf` |
| Events | `admin.php?page=wf-sn#sn_logger` |
| Login (Pro) | `admin.php?page=wf-sn#sn_login` |
| Scheduler (Pro) | `admin.php?page=wf-sn#sn_schedule` |
| Malware (Pro) | `admin.php?page=wf-sn#sn_malware` |
| AI Security Advisor | `admin.php?page=wf-sn-advisor` |

Read the screen before changing settings. Prefer the admin UI over editing options in the database.

## Read results

1. **Tests.** Failed first, then warnings. A red test is a misconfiguration to review, not proof the site is hacked. A green board is not a guarantee.
2. **Vulnerabilities.** The warning headline means a known issue matched an installed plugin, theme, or WordPress version. Update to the version the card names, or remove the plugin. Collapsed Details still has the write-up. Do not mark something vulnerable unless this tab (or an Ability) says so.
3. **Core scanner.** Review modified and unknown files before restore or delete. Extra files in core folders are not automatically malware.
4. **Events.** Firewall blocks and failed or successful logins. Use a block row to see which request was stopped before turning a rule off.
5. **AI report.** Latest saved audit is on the Advisor page. It is a summary of stored scans, not a new exploit finder.

There is no multi-site phone-home API in the plugin. Do not invent a REST or MCP endpoint for fleet dashboards.

### WordPress Abilities (same site, WordPress 7)

Read-only. Require `manage_options`. Shown in REST when exposure is on (Advisor settings, on by default). They do not change the site.

- `security-ninja/get-test-summary` returns passed, warning, and failed counts
- `security-ninja/get-attack-activity` returns the last 7 days versus the previous 7 days
- `security-ninja/get-latest-report` returns the latest stored Advisor report

## Harden checklist

Work in this order. Stop and show the site owner anything destructive (delete a file, disable a rule, change `wp-config.php`).

1. Run **Security Tests**. Fix failed items the owner agrees with. Headers, XML-RPC, file editor, and debug mode are on the Pro **Fixes** page. On free, describe the change and let the owner apply it.
2. Open **Vulnerabilities**. Update or replace each flagged plugin or theme. Upgrade WordPress when core is flagged.
3. Open **Core scanner**. Restore official core files that were modified without a reason. Do not delete an unknown file until you know what it is.
4. Confirm the **firewall** is on. If a real checkout, webhook, or login is blocked, identify that request in Events and narrow the rule. Do not turn the firewall off to silence it.
5. On Pro: malware scan, failed-login limits, and 2FA for administrators. Schedule scans only after the first manual pass looks right.
6. Re-run tests and the vulnerability scan. Report what changed, what is still open, and what is Pro-only.

## Do not

- Paste license keys, `wp-config.php` secrets, or full attack payloads into chat.
- Disable the firewall, 2FA, or login protection unless the site owner asked, and say what protection they are dropping.
- Claim a CVE, a malware hit, or a failed test that you did not read from this site.
- Edit anything under `vendor/` or the Freemius SDK.
- Treat this skill as permission to change another plugin's code to "pass" a test.
