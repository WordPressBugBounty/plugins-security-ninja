<?php
/**
 * Free User Render Functions
 *
 * @package Security Ninja
 * @subpackage Free User Experience
 * @author Lars Koudal
 * @since v0.0.1
 * @version v1.0.0 Tuesday, December 7th, 2021.
 */

namespace WPSecurityNinja\Plugin;

/**
 * Handles rendering of free user experience pages for premium features
 */
class Free_Render {

	/**
	 * Renders the events logger page for free users
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, December 7th, 2021.
	 * @access  public static
	 * @return  void
	 */
	public static function render_events_logger_page() {
		echo '<div class="submit-test-container">';
		?>
		<div class="fomcont">
			<h3>Events Logger: Track and monitor site activity</h3>

			<img src="<?php echo esc_url( WF_SN_PLUGIN_URL . 'images/event-log.jpg' ); ?>" alt="Track and monitor site activity" class="tabimage">

			<p>
				Keep a detailed record of everything happening on your site with Events Logger. Monitor user logins, file changes, plugin updates, and more to maintain complete visibility over your WordPress installation.
			</p>
			<p>
				Events Logger provides comprehensive logging capabilities that help you track suspicious activity, troubleshoot issues, and maintain compliance requirements. With detailed event records and powerful filtering options, you'll always know what's happening on your site.
			</p>
			<ul>
				<li><strong>Comprehensive Activity Tracking:</strong> Monitor user logins, file modifications, plugin changes, and other critical events automatically.</li>
				<li><strong>Advanced Filtering:</strong> Quickly find specific events using powerful search and filter options to focus on what matters most.</li>
				<li><strong>Detailed Event Information:</strong> Get complete context for each event including user details, timestamps, and related data.</li>
				<li><strong>Export Capabilities:</strong> Export logs for external analysis, compliance reporting, or backup purposes.</li>
				<li><strong>Real-Time Monitoring:</strong> Stay informed with immediate logging of all site activities as they happen.</li>
			</ul>
			<p>
				<em>Don't let important activities go unnoticed—activate Events Logger and maintain complete visibility over your WordPress site.</em>
			</p>
			<p class="fomlink"><a target="_blank" href="<?php echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'tab_events_logger', '/events-logger/' ) ); ?>" class="button button-primary" rel="noopener">
				<?php esc_html_e( 'Learn more', 'security-ninja' ); ?>
			</a></p>
		</div>
		<?php
		echo '</div>';
	}

	/**
	 * Renders the cloud firewall page for free users
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, December 7th, 2021.
	 * @access  public static
	 * @return  void
	 */
	public static function render_cloudfw_page() {
		echo '<div class="submit-test-container">';
		?>
		<div class="fomcont">
			<h3>Advanced Firewall: Proactive Security for Your Site</h3>

			<img src="<?php echo esc_url( WF_SN_PLUGIN_URL . 'images/firewall.jpg' ); ?>" alt="<?php esc_html_e( 'Scan Core files of WordPress', 'security-ninja' ); ?>" class="tabimage">

			<p>
				Protect your website and your reputation with Firewall, your always-on security partner. Instantly block hackers, malware, and suspicious activity before they can do any harm. With Firewall, you get peace of mind knowing your site is shielded by both powerful local protection and a constantly evolving global threat database. Enjoy more control, fewer worries, and a safer experience for you and your visitors.
			</p>
			<ul>
				<li><strong>Local Firewall Protection:</strong> Stop threats at the door with real-time monitoring and blocking of suspicious requests, right on your site.</li>
				<li><strong>Global Threat Intelligence:</strong> Benefit from a dynamic database of over 600 million known malicious IP addresses, updated every six hours using data from millions of sites worldwide.</li>
				<li><strong>Login Protection:</strong> Defend your login page with repeated failed login blocking, brute force prevention, and built-in two-factor authentication (2FA) for extra security.</li>
				<li><strong>Country Blocking:</strong> Instantly restrict access from any country to keep your site safe from targeted regions.</li>
				<li><strong>Manual Whitelisting &amp; Blacklisting:</strong> Take full control by manually allowing or blocking specific IP addresses as needed.</li>
				<li><strong>Custom Block Responses:</strong> Show a personalized message to blocked visitors or redirect them to any URL you choose.</li>
			</ul>
			<p>
				<em>Give your site the proactive protection it deserves—activate Firewall and stay one step ahead of online threats.</em>
			</p>

			<p class="fomlink"><a target="_blank" href="<?php echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'tab_firewall', '/cloud-firewall/' ) ); ?>" class="button button-primary" rel="noopener">
				<?php esc_html_e( 'Learn more', 'security-ninja' ); ?>
			</a></p>
		</div>
		<?php
		echo '</div>';
	}

	/**
	 * Renders the malware scanner page for free users
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, December 7th, 2021.
	 * @access  public static
	 * @return  void
	 */
	public static function render_malware_page() {
		echo '<div class="submit-test-container">';
		?>
		<div class="fomcont">
			<h3>Malware scanner: Detect and eliminate hidden threats</h3>

			<img src="<?php echo esc_url( WF_SN_PLUGIN_URL . 'images/malware-scanner.jpg' ); ?>" alt="Find malicious files in your WordPress site" class="tabimage">

			<p>
				Even the most secure websites can fall victim to malware. With Firewall and strong passwords, you're already a step ahead—but hidden threats can still slip through.
			</p>
			<p>
				That's where the Malware Scanner comes in. Enjoy peace of mind knowing your site is regularly checked for malicious code, suspicious changes, and known attack patterns. Protect your reputation, your visitors, and your business with fast, thorough scans and clear results.
			</p>
			<ul>
				<li><strong>Comprehensive Site Scanning:</strong> Quickly scan your entire website for code commonly found in malicious scripts and known attack signatures.</li>
				<li><strong>Plugin Integrity Checks:</strong> Every public plugin from WordPress.org is verified against a master checklist to detect unauthorized file changes or tampering.</li>
				<li><strong>Real-Time Alerts:</strong> Get instant notifications if suspicious code or modifications are found, so you can act before any damage is done.</li>
				<li><strong>Easy-to-Understand Reports:</strong> See exactly what was scanned, what was found, and what steps to take next—no technical jargon required.</li>
				<li><strong>Continuous Protection:</strong> Schedule regular scans to keep your site safe around the clock.</li>
			</ul>
			<p>
				<em>Don't let hidden threats compromise your hard work—activate Malware Scanner and keep your site clean, safe, and secure.</em>
			</p>
			<p class="fomlink"><a target="_blank" href="<?php echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'tab_malware', '/malware-scanner/' ) ); ?>" class="button button-primary" rel="noopener">
				<?php esc_html_e( 'Learn more', 'security-ninja' ); ?>
			</a></p>
		</div>
		</div>
		<?php
	}

	/**
	 * Renders the scheduled scanner page for free users
	 *
	 * @author  Lars Koudal
	 * @since   v0.0.1
	 * @version v1.0.0  Tuesday, December 7th, 2021.
	 * @access  public static
	 * @return  void
	 */
	public static function render_scheduled_scanner_page() {
		echo '<div class="submit-test-container">';
		?>
		<div class="fomcont">
			<h3>Scheduled Scanner: Automated security monitoring</h3>

			<img src="<?php echo esc_url( WF_SN_PLUGIN_URL . 'images/scheduler.jpg' ); ?>" alt="Automated security monitoring" class="tabimage">

			<p>
				Set up automated security scans that run on your schedule, not when you remember. Scheduled Scanner ensures your site is regularly checked for vulnerabilities, malware, and security issues without requiring manual intervention.
			</p>
			<p>
				Configure scans to run daily, weekly, or monthly based on your needs. Receive detailed reports via email, and rest easy knowing your site is being monitored even when you're not actively managing it.
			</p>
			<ul>
				<li><strong>Flexible Scheduling:</strong> Set up scans to run automatically on your preferred schedule—daily, weekly, or monthly.</li>
				<li><strong>Comprehensive Coverage:</strong> Scan for vulnerabilities, malware, and security issues in one automated process.</li>
				<li><strong>Email Notifications:</strong> Receive detailed reports via email with clear summaries of findings and recommendations.</li>
				<li><strong>Custom Scan Profiles:</strong> Configure different scan types and depths based on your security requirements.</li>
				<li><strong>Historical Tracking:</strong> Maintain a complete history of scan results to track security improvements over time.</li>
			</ul>
			<p>
				<em>Don't let security monitoring fall through the cracks—activate Scheduled Scanner and maintain consistent protection for your site.</em>
			</p>
			<p class="fomlink"><a target="_blank" href="<?php echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'tab_scheduled_scanner', '/scheduled-scanner/' ) ); ?>" class="button button-primary" rel="noopener">
				<?php esc_html_e( 'Learn more', 'security-ninja' ); ?>
			</a></p>
		</div>
		<?php
		echo '</div>';
	}
} 