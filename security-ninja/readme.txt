=== Security Ninja – WordPress Security & Firewall ===
Contributors: lkoudal, cleverplugins, freemius
Donate link: https://wpsecurityninja.com/?utm_source=wordpressorg&utm_medium=content&utm_campaign=readme&utm_content=donate
Tags: security, firewall, waf, vulnerability, malware
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html
Requires at least: 4.7
Tested up to: 7.1.2
Stable tag: 5.310
Requires PHP: 7.4

WordPress security plugin: free 8G firewall/WAF, 50+ tests, vulnerability/core scanning, events logging, AI reports.

== Description ==

Security Ninja is a lightweight **WordPress security plugin** that helps protect your site from common attacks and security mistakes - without turning your dashboard into a cockpit.

[youtube https://www.youtube.com/watch?v=x8GZCnywMhE]

**Web Application Firewall (WAF)** (based on the 8G ruleset) to block common malicious requests, plus 50+ security checks, a full vulnerability scanner, and a core integrity scanner to spot risky settings and unexpected file changes.

Upgrade to Pro for Cloud Firewall, malware scanning/cleanup, login brute-force protection and 2FA, export/webhooks, and scheduled scans.

This plugin can be downloaded for free without any paid subscription from <a href="https://wordpress.org/plugins/security-ninja/">the official WordPress repository</a>.



**Included for free**
- **Basic Firewall (8G-based)** – Blocks common malicious requests and bot noise before it becomes a problem.
- **50+ Security Tests** – Fast audit of common WordPress security misconfigurations.
- **Vulnerability Scanner** – Highlights known issues in plugins/themes so you can patch faster.
- **Core Scanner** – Detect modified or unexpected files in WordPress core folders.
- **Basic Events Logger** – Logs **firewall events** and **login attempts (successful/failed)**.
- **AI Security Advisor (WordPress 7)** – AI-generated audit summaries and guided follow-ups from your scans, using WordPress AI Connectors (you choose the LLM provider). Optional WordPress Abilities let other AI tools on your site read test summaries, attack activity, and your latest saved report.

**Pro adds**
- **Cloud Firewall & advanced WAF** – Block 600+ million known bad IPs, country blocking, IP management, and stronger firewall controls (free includes the 8G-based firewall).
- **Advanced Malware Scanner** – Detect and clean malicious code and suspicious files.
- **Login protection & 2FA** – Limit failed logins, rename the login URL, and add two-factor authentication.
- **One-click Fixes** – Harden WordPress from the Fixes page (XML-RPC, file editor, headers, and more).
- **Full Events Logger** – Export logs, scheduled email reports, webhooks (e.g. Slack/Discord), and deeper alerting.
- **Scheduled scans & reporting** – Automated security scans and reports.


**Key Features**

Security Ninja is a lightweight **WordPress firewall plugin** and security toolkit designed to help you find misconfigurations, block common attacks, and stay ahead of known vulnerabilities - without slowing your site down.

**Comprehensive WordPress Security Testing**

Security Ninja performs 50+ advanced security tests to identify issues before attackers exploit them. This includes:

- **Login and password checks** – Audits weak passwords and related settings (Pro adds failed-login limits, rename login, and 2FA).
- **File integrity monitoring** – Detects unauthorized changes to WordPress core files, themes, and plugins.
- **Database security checks** – Identifies weak database permissions and potential SQL injection threats.
- **User role audits** – Ensures no unauthorized administrator accounts exist.
- **Security misconfiguration scans** – Identifies and fixes weak settings that could compromise security.

**Enhanced Vulnerability Scanner**

Proactively alerts you to known vulnerabilities in plugins and themes so you can patch before they are exploited.

**Core Scanner – WordPress Installation Integrity**

Ensures your WordPress installation remains untampered and free of unauthorized files.

- **Full core file integrity check** – Scans every file in core WordPress folders for modifications.
- **Unknown file detection** – Flags extra or unexpected files in core directories.
- **Built-in file viewer** – Review flagged files in the dashboard.
- **Restore or delete** – Restore altered core files with one click, or remove suspicious unknowns.


**Advanced Malware Scanner – Detect & Remove Malware Instantly (PRO)**

Security Ninja includes a high-performance malware scanner that automatically checks your WordPress core, plugins and themes for:

- **Malicious scripts and backdoors** – Identifies hidden malware and harmful injections.
- **Trojan and virus detection** – Scans for suspicious PHP and JavaScript entries.
- **One-click malware removal** – Instantly quarantine and delete infected files.

**WordPress Firewall & Real-Time Threat Protection**

Security Ninja includes a **basic firewall for free** (8G-based) to block common malicious requests. Upgrade to Pro for more advanced WAF controls.

- **Basic protection (Free)** – 8G rules block many common exploit patterns and abusive requests.
- **Advanced protection (Pro)** – Cloud Firewall, country blocking, IP lists, and additional intelligence/automation.
- **Login brute-force protection (Pro)** – Limit failed logins and harden the login flow (not included in the free firewall).

**Automatic service whitelisting (Pro)**

Cloud Firewall (Pro) whitelists known third-party service IPs so remote maintenance, optimization, and monitoring tools are less likely to be blocked. No manual IP entry is required for these built-in lists.

- **WP Compress** – image optimization and compression service
- **MonSpark** – uptime and website monitoring
- **Modular DS** – remote site management
- **WPMU DEV** – hosting and management platform
- **Divi Dash** – Elegant Themes site management
- **Fastpixel** – optimization service
- **Broken Link Checker** – link checking service
- **GetTerms** – cookie consent scanner (getterms.io)

**Optional one-click whitelists** (Firewall → IP Management; enable per service):
- **ManageWP** – enabled by default on new installs
- **WP Rocket** – caching and optimization
- **UptimeRobot** – uptime monitoring
- **Uptimia** – uptime monitoring

You can still add your own IPs and CIDR ranges manually on the IP Management screen.

**Login Security & Two-Factor Authentication (2FA) (PRO)**

Your WordPress login page is a primary target for hackers. Security Ninja enhances login security with:

- **Two-Factor Authentication (2FA)** – Requires additional verification for safer logins.
- **Brute-force attack protection** – Limits failed login attempts to block unauthorized access.
- **Rename login** - Getting a lot of requests to your login form? Hide it for spammers.

**One-Click Security Fixes & WordPress Hardening (PRO)**

Manually fixing security issues is time-consuming. Security Ninja provides one-click hardening to:

- **Disable XML-RPC** – Blocks common DDoS attacks and brute-force exploits.
- **Restrict file editing** – Prevents unauthorized theme and plugin modifications.
- **Hide PHP error messages** – Stops hackers from exploiting sensitive error details.

And many more fixes to harden your WordPress security!

**Events Logger / Activity Tracking**

Security Ninja includes a **basic events logger for free** so you can see what’s happening on your site.

- **Free:** firewall events and login attempts (successful/failed) in the dashboard.
- **Pro:** export security logs, scheduled email reports, webhooks (e.g. Slack/Discord), and deeper alerting.

**Automated Security Scans & Reports (PRO)**

Security Ninja performs scheduled security scans and sends reports directly to your inbox.

- Set up daily, weekly, or monthly security scans.
- Receive email alerts about vulnerabilities and malware infections.
- Analyze detailed reports to keep your website secure.

**Block Spam & Malicious Bots Instantly (PRO)**

Hackers and spammers use bots to exploit WordPress websites. Security Ninja prevents:

- **Fake registrations and spam comments** – Stops bots from even getting to your site.
- **Malicious bot attacks** – Blocks scripts attempting to hack your site.
- **Unwanted traffic** – Reduces server load by preventing unnecessary bot access.

**AI Security Advisor - from scan results to clear next steps (WordPress 7)**

Understanding a security scan shouldn’t feel like homework. **AI Security Advisor** uses your connected LLM (via **WordPress 7 AI Connectors**) to turn Security Ninja findings into a readable audit: executive summary, prioritized improvements, and suggested follow-up prompts-not an open-ended chatbot.

Reports draw on Security Tests, the Vulnerability Scanner, Core Scanner, recent firewall/login events, and on Pro sites Malware Scanner results when available. Saved reports stay on your site until you remove them.

**What you need**  
AI Security Advisor is included in the free plugin but requires **WordPress 7**. You connect the AI/LLM provider yourself under **Settings → Connectors** in WordPress; Security Ninja does not host or supply API keys.

**WordPress Abilities (optional)**  
On WordPress 7, Security Ninja can register read-only **Abilities** so other AI tools on the same site can fetch a test summary, 7-day attack activity, or your latest saved audit-useful if you use multiple AI integrations. Report generation and follow-ups on the Security Advisor page work independently of this.

**Privacy, in everyday language**  
Only non-identifying security context (test results, scan status, event counts-not personal data) is sent to your chosen AI provider to build a report.

If you are not on WordPress 7 yet, you will see a notice on the AI Security Advisor screen; the rest of Security Ninja continues to work as usual.

---

**Join thousands of satisfied users who trust Security Ninja to keep their websites safe. Start protecting your online presence today.**

===Extensions===
**MainWP** - Manage Security Ninja across many sites from one MainWP Dashboard. Security Ninja on each child site includes MainWP integration built in (no extra plugin on child sites).

* **Free addon** - <a href="https://wordpress.org/plugins/security-ninja-for-mainwp/" target="_blank">Security Ninja for MainWP</a> (WordPress.org): view test results and vulnerabilities per site, trigger remote security scans, and sync fresh results. Works with child sites on free or Pro Security Ninja; data shown matches what each site’s installed version provides.
* **Premium addon** - Adds a combined events log across all connected sites, search/filter for security events, and remote white-label control on Pro child sites. Requires Security Ninja Pro on child sites for log and white-label features. Available from your <a href="https://wpsecurityninja.com/account/?utm_source=wordpressorg&utm_medium=content&utm_campaign=readme&utm_content=account" target="_blank">WP Security Ninja account</a>; see <a href="https://wpsecurityninja.com/mainwp/?utm_source=wordpressorg&utm_medium=content&utm_campaign=readme&utm_content=mainwp" target="_blank">MainWP integration</a> for details.

https://wordpress.org/plugins/security-ninja-for-mainwp/


> **Security Ninja Pro** adds Cloud Firewall (600+ million known bad IPs), country blocking, advanced WAF controls, Malware Scanner, login protection (failed-login limits, rename login, 2FA), One-click Fixes, full Events Logger (export, webhooks, scheduled reports), and scheduled scans. The free plugin already includes the 8G firewall, 50+ security tests, Vulnerability Scanner, Core Scanner, basic Events Logger, and AI Security Advisor on WordPress 7.

An all-in-one security solution for any site. With premium support and continuous updates Security Ninja **Pro** is a perfect tool to keep your site safe. <a href="https://wpsecurityninja.com/?utm_source=wordpressorg&utm_medium=content&utm_campaign=readme&utm_content=see-what-pro-offers">See what the PRO version offers</a>

Automatically block **600+ million bad IPs** with one click! <a href="https://wpsecurityninja.com/?utm_source=wordpressorg&utm_medium=content&utm_campaign=readme&utm_content=cloud-firewall">Security Ninja Pro Firewall</a> will help you stay one step ahead of bad guys by using the collective know-how of millions of attacked sites, and ban bad guys before they even open your site.

> Read more about Pro features on the <a href="https://wpsecurityninja.com/?utm_source=wordpressorg&utm_medium=content&utm_campaign=readme&utm_content=readmoreaboutpro">Security Ninja website</a>

**What others say about the plugin**

* <a href="https://kinsta.com/blog/wordpress-security-plugins/">Kinsta</a>
* <a href="https://www.hostinger.com/tutorials/wordpress-security-plugins">Hostinger</a>
* <a href="https://www.cloudways.com/blog/best-wordpress-security-plugins/">Cloudways</a>
* <a href="https://appsumo.com/products/wp-security-ninja/">AppSumo</a>
* <a href="https://freemius.com/blog/security-best-practices-developing-plugins-themes/">Freemius</a>
* <a href="https://wpmayor.com/security-ninja-review-wordpress-security-plugin/">WP Mayor: "Easy-to-Use WordPress Security Plugin"</a>
* <a href="https://wpmarmite.com/en/compare/best-wordpress-security-plugins/security-ninja/">WPMarmite</a>
* <a href="https://www.wpexplorer.com/">WPExplorer</a>
* <a href="https://wplift.com/">WPLift</a>
* WP Loop
* <a href="https://influencewp.com/">InfluenceWP</a>
* <a href="https://www.g2.com/products/wp-security-ninja/reviews">G2</a>

**Tests**
* The tests include:
  * brute-force attack on user accounts to test password strength
  * numerous installation parameters tests
  * file permissions
  * version hiding
  * 0-day exploits tests
  * debug and auto-update modes tests
  * database configuration tests
  * Apache and PHP related tests
  * WP options tests
  * security headers and related server response checks

* The full suite covers 50+ checks across WordPress core/plugins/themes, user accounts and passwords, file permissions, debug modes, database configuration, PHP settings, security headers, and more. Open Security Ninja in your dashboard for the complete list with explanations and fix guidance.

**License info**

* <a href="https://github.com/carhartl/jquery-cookie">jQuery Cookie Plugin, Copyright 2013 Klaus Hartl</a>

* The vulnerability scanner uses data from the <a href="https://nvd.nist.gov/">National Vulnerability Database - NVD</a>

* This product includes IP2Location LITE data available from <a href="https://lite.ip2location.com">https://lite.ip2location.com</a>.

* This plugin uses the <a href="https://github.com/collizo4sky/persist-admin-notices-dismissal">Persist Admin notice Dismissals</a> by Collins Agbonghama @collizo4sky

* Firewall rules are based on 8G Firewall by Jeff Starr - https://perishablepress.com/8g-blacklist/

= How can I report security bugs? =

You can report security bugs through the Patchstack Vulnerability Disclosure Program. The Patchstack team help validate, triage and handle any security vulnerabilities. [Report a security vulnerability.](https://patchstack.com/database/vdp/security-ninja)


== Installation ==

= Installing from WordPress =

1. Open WordPress admin, go to Plugins, click Add New
2. Enter "Security Ninja" in search and hit Enter
3. Plugin will show up as the first on the list, click "Install Now"
4. Activate & go to Tools - Security Ninja to make your site more secure

= Installing Manually =

1. Download the plugin.
2. Unzip it and upload to _wp-content/plugin/_
3. Open WordPress admin - Plugins and click "Activate" next to the plugin
4. Activate & go to Security Ninja to make your site more secure

== Frequently Asked Questions ==

= Does the free version include a WordPress firewall (WAF)? =
Yes. Security Ninja includes a **basic Web Application Firewall (WAF) for free**, based on the 8G ruleset. It blocks common malicious requests and reduces bot noise.

= Does Security Ninja protect against brute force attacks and login attempts? =
**Pro** includes login brute-force protection (failed-login limits), rename login, and 2FA. The **free** version records login attempts (successful/failed) in the Events Logger and runs security tests that check password strength-it does not block repeated failed logins on its own.

= Does Security Ninja include a WordPress vulnerability scanner? =
Yes. The **Vulnerability Scanner is fully available in the free version** and helps you identify known vulnerabilities in plugins/themes so you can patch quickly.

= Who is this plugin for? =
Site owners, agencies, and developers who want a lightweight WordPress security plugin to harden sites and catch problems early.

= Will this plugin slow down my site? =
In normal operation, no. Some scans can temporarily use more resources while they run.

= What changes will Security Ninja make to my site? =
Security Ninja runs checks and shows recommendations. Some Pro features can add active protection layers (firewall/WAF controls, login protection), which you can configure.

= What if I encounter issues with the plugin? =
While we strive for universal compatibility, if you face any issues, our support team is ready to assist. Visit our [support forum](https://wordpress.org/support/plugin/security-ninja) to open a new thread, and we'll help you as soon as possible.


== Screenshots ==

1. Firewall & Events overview (blocked requests + quick stats).
2. Firewall Events log (see what was blocked and why).
3. Vulnerability Scanner (find vulnerable plugins/themes and patch fast).
4. Security Tests (one-click audit with clear pass/fail results).
5. Core Scanner (detect modified/unknown core files).

== Changelog ==

Recent releases are below. The full history is on <a href="https://wpsecurityninja.com/changelog/?utm_source=wordpressorg&utm_medium=content&utm_campaign=readme&utm_content=changelog">wpsecurityninja.com/changelog/</a>.

= 5.310 =
* 2026-11-10
* FIX: Firewall - Turning Pro off, or turning the firewall off, no longer leaves a 15-minute job that WordPress cannot reschedule. The job is removed, so the log stays quiet.
* FIX: Tests - Site Address vs WordPress Address no longer fails on server cron when HTTPS is off. Both URLs are compared with the same scheme. Manual scans in the browser were already fine. Thank you Torsten.
* IMPROVED: Scheduled Scanner - Agencies can temporarily keep specific tests out of the status-change email with the <code>wf_sn_ss_email_ignore_tests</code> filter. The tests still run and still show in the dashboard. Thank you Torsten.

= 5.309 =
* 2026-11-09
* FIX: Two-Factor Authentication - Switching mobile network or proxy between the password and the code no longer blocks email 2FA or the login session. IP and browser changes are still logged. Thank you Ryan.
* FIX: Two-Factor Authentication - "Remember this browser" on the code screen is clickable again.
* FIX: Emails - Failed login warnings no longer begin with leftover PHP from the email template (some mail filters treated that as spam). The same template fix covers the secret access link, two-factor code, and scheduled scan emails. Failed login warnings also include a plain-text copy. Thank you Tyson.
* FIX: Malware Scanner - ThinkRank Pro redirect and SEO field-resolver files are no longer false positives. Thank you Kathryn / WPDeveloper.
* FIX: Core Scanner - Diff and Restore only use a WordPress.org file after it matches the official checksum. If the download cannot be verified, nothing is restored. Non-English sites use checksums for their own language. Thank you Tim.
* FIX: Firewall and Events - Missing PHP BCMath no longer breaks the page on IPv6 lookups. Country is skipped for that address; the Events log and front end (including Elementor) keep loading. Enable BCMath if you want countries for IPv6. Thank you Tom and Vahid.
* FIX: Firewall - With Early Firewall on, country blocking still applies to dashboard AJAX requests after the early IP check.
* IMPROVED: Early Firewall - No longer labeled as beta. It stays optional and off until you enable it (it changes server setup for that site).
* IMPROVED: Malware Scanner - Database and persistence checks are back and marked Beta. They flag known bad plugin and must-use names, hidden folders that match known malware naming patterns, and suspicious option values. Thank you Tim.
* FIX: Malware Scanner - Option-value scanning ignores ordinary plugin text, long keys and hashes, short function names that appear in normal docs, and normal widget iframes.
* IMPROVED: Malware Scanner - Clearer scan progress with live counters, one results table with filters and paging, and safer delete actions for options, cron events, and folders.
* FIX: Malware Scanner - Early Firewall recovery snapshots are no longer listed as malware.

= 5.308 =
* 2026-11-03
* FIX: Vulnerability Scanner - The "plugins checked" and "themes checked" numbers now match what is installed. A plugin with many known issues was counted once for each database row, and a theme with no known issues was reported as 0. The scan was already checking the installed list. Run the scan again after updating so the event log shows the new numbers. Thank you Werner.
* IMPROVED: Two-Factor Authentication - Login Protection can let a browser skip 2FA for a set number of days after a successful code. It stays off until you set the days (up to 90). The person still ticks "Remember this browser" on the code screen. A password change from the profile screen or the reset email, or resetting 2FA, asks for a code again. Lowering the days cuts short a browser that was remembered for longer. The number is included in Tools import/export. An older export that does not have it leaves the number already on the site. Thank you Torsten.
* IMPROVED: Two-Factor Authentication - Backup codes are shown when 2FA setup finishes. The person confirms they have saved them before continuing. Each code is shown once and works once. A password change, or resetting 2FA, deletes the codes. A new set can be created later from the profile.
* FIX: Two-Factor Authentication - The login session created by the password is destroyed before the code screen. The code is checked for the account that passed the password step. A user id sent with the code is ignored. Wrong codes, including backup codes, still count toward lockout, and a blocked IP is not checked for a code.
* FIX: Two-Factor Authentication - "Remember this browser" on the code screen can be ticked. The verify button no longer sits on top of it.
* FIX: Scheduled Scanner - The email names the security test that changed, including the previous result when the message changed. Core files are listed only when they are new or no longer listed. A file that was already reported does not send another change email by itself.

= 5.307 =
* 2026-11-01
* Login, firewall, and scan updates. Your saved settings stay as they are.
* FIX: Firewall - Filter Suspicious Queries no longer treats ordinary text as an attack. A MapPress title such as "Scharfenstein (Rangerstation)" is not a function call, and neither is "Charlotte (Charlie)" or "Functions (overview)". The function name has to stand on its own and be followed by a parenthesis. Real exploit-style calls are still blocked. Words such as "evaluation" or "medieval" are not treated as code execution. A phrase such as "please select one" is no longer treated as SQL. Common SQL verbs are still blocked when real query syntax follows. A parameter that only ends in _request, such as download_request, is no longer treated as access to the request array. Thank you Torsten and Kevin.
* FIX: Core Scanner - WordPress 7 files under wp-includes/php-ai-client/ that were saved with a shortened name are no longer listed as critical unknown files. When the file matches the official checksum, the scan explains the shortened name and can rename it back. Those files are left out of "Delete critical & warning unknowns".
* FIX: Firewall - A saved coupon limit of 3 (the minimum is now 5) no longer blocks saving the other firewall tabs. The field sits on the Store tab in the same form, and the browser was refusing to submit it. Thank you Chris.
* IMPROVED: Two-Factor Authentication - Repeated wrong codes now use the same limit as failed logins (default 5 tries in 5 minutes). The wait stays in place until that window ends. With the firewall on, those tries count the same way a wrong password does.
* IMPROVED: Events Logger - An incorrect 2FA code is saved in the events log with the account name. With the firewall on, the same try is also listed as a failed login.
* IMPROVED: Two-Factor Authentication - Authenticator app secrets now follow your WordPress salts. The update re-encrypts existing secrets the next time you open wp-admin. Email codes are unchanged. If you later change AUTH_KEY or SECURE_AUTH_KEY, those users set up the app again.
* FIX: Early Firewall - Block events waiting to be logged are stored as data files. An event that had not been written to the log yet may be missing once after this update.
* FIX: Login Protection - The hidden wp-admin check now confirms the login cookie is valid. A normal login is unchanged.
* FIX: Core Scanner - "Delete critical and warning unknowns" leaves files in the site root alone, including wp-config.php. You can still remove one of those files from its own row.
* IMPROVED: Core Scanner ignores HTML challenge pages when it downloads official file content for a diff or restore.
* IMPROVED: Firewall IP Management shows Unblock for temporary local bans and 404 Guard bans.
* IMPROVED: Visitor Log stays on the current page after you ban an IP from the log.
* IMPROVED: MainWP - The child connection is available whenever MainWP Child is active on the site.

= 5.306 =
* 2026-10-21
* NEW: Login Protection - Optional "Redirect /wp-admin to homepage" when Change login URL is on. Logged-out visitors who open /wp-admin or /wp-login.php go to the homepage instead of Access Denied. Off by default. Does not reveal the new login URL. Included in Tools import/export and MainWP settings sync. Thank you Torsten for the suggestion.
* FIX: Firewall - Filter Suspicious Queries no longer treats bare "..." in query values as path traversal (masked card numbers, truncated text). Real traversal such as ../, ..\\, and encoded variants still match. Thank you Kevin.
* FIX: Early Firewall - After a plugin update, the compiled WAF config is rebuilt automatically so rule changes apply. If rebuild fails, Extended Protection shows an error instead of silently keeping old rules. Early Firewall is still in beta but proving very stable so far from the feedback we get.
* FIX: Early Firewall - Pre-install recovery snapshots are stored as .wfbkp JSON (not .php), so the Malware Scanner no longer flags our own recovery files as Critical. Thank you 学而図書.
* FIX: Firewall / WooCommerce - Coupon protection counts one failed apply per request (Woo can fire the error filter twice), logs the real coupon code instead of the numeric error id, returns a normal coupon error instead of killing the request, and no longer blocks placing an order when only coupons are temporarily limited. Default failed-attempt limit is 10 (minimum 5). Thank you Manfred.
* FIX: Fixes - Security header names stay in English in every language. No more translated titles.
* IMPROVED: Firewall - Referrer and blocked-host matches stay on the site.
* IMPROVED: Firewall - IP Management. IP and status columns stay narrow so notes and last visit have the room. Last visit shows the relative time and the date. Long lists stay at 25 per page.

= 5.305 =
* 2026-10-11
* IMPROVED: German - The bundled translation now uses Du, the same terms throughout (Schwachstelle, Core-Scanner, Malware-Scanner, Korrekturen, Anmeldung), and the strings that were still English are translated.
* FIX: Tests - A wp-config.php moved one level above the WordPress root now scores as a pass. A file still in the root stays a warning. Thank you Robert.
* IMPROVED: Updated Freemius SDK to the latest version.
* NEW: Agent skill - SKILL.md in the plugin folder tells Cursor and Claude-style agents how to configure Security Ninja, read scan results, and work through a harden checklist. This is separate from the WordPress Abilities API. Thank you Gabe.
* IMPROVED: Vulnerability Scanner - When vulnerabilities are found, the warning is the only headline. "Vulnerability Scanner" stays when the scan is clean or still running. Collapsed Details no longer leaves an empty white bar.
* FIX: Auto Fixer - File backups are stored as .wfbkp data files again (not .php), so the Malware Scanner no longer flags our own backups. Existing .wfbkp.php backups are migrated automatically. Thank you Tom and Masahiro.
* IMPROVED: Tests - Permissions-Policy example now uses current header syntax and a shorter default that leaves fullscreen, autoplay, and encrypted media alone so embedded video keeps working. Thank you Lee.
* IMPROVED: Tests - Permissions-Policy default no longer disables payment, so Apple Pay and Google Pay checkouts keep working. Thank you Robert.
* IMPROVED: Tests - Content-Security-Policy help and Fixes examples use a WordPress-safe enforcing policy. Script limits stay an advanced step and will not pass the test while they are Report-Only. Thank you Robert.
* IMPROVED: Tests - MySQL permissions warns when the account has ALL PRIVILEGES on this site's database, and fails on global grants or GRANT OPTION. The help text lists the privileges WordPress, updates, and backups need. Thank you Robert.
* IMPROVED: Tests - Security header help cleanup: removed obsolete X-Frame-Options ALLOW-FROM, fixed CSP Apache Header set syntax, and aligned X-Content-Type-Options, X-Frame-Options, HSTS, and Referrer-Policy PHP examples with the wp_headers filter.
* IMPROVED: Fixes - Hide WP Version now also clears the generator on RSS/Atom feeds and strips matching WordPress core ?ver= from CSS/JS asset URLs. Plugin and theme cache-busting versions are left alone.
* FIX: Scheduled Scanner - Scans started through Action Scheduler's async admin-ajax runner no longer die on a Security Ninja test nonce check (403). Internal runners skip that AJAX nonce; UI AJAX still verifies it. Thank you Kevin.
* IMPROVED: Firewall - Block IP Network now uses api.wpsecurityninja.com. User-agent matches stay local and are no longer sent to the shared list. Sites with the feature on download the shared list once a day.
* IMPROVED: Firewall - Block IP Network reports are queued locally and flushed in batches (every 15 minutes or at 25 unique IPs), with a local hit count per IP.
* IMPROVED: Firewall - Early Firewall 8G blocks are reported to the Block IP Network when WordPress imports them. User-agent matches stay local.
* FIX: Firewall - Repeated failed logins are reported to the Block IP Network as repeat_failed_login, which is the type the shared list accepts.
* IMPROVED: Events Logger - Selected firewall and block events, including Early Firewall blocks and lost-password bans, are kept for 90 days. Other events still follow the retention you set.
* IMPROVED: Firewall - Country block selection stays as you set it when you press Enter in another field on the Firewall settings page.
* IMPROVED: Firewall - Request URI checks use the path only. Query parameters are checked separately, so long tokens in URLs (for example WooCommerce download links) are not mistaken for exploit paths.
