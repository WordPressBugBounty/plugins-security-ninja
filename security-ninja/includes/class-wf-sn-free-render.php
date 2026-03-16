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
			<p class="fomlink"><a target="_blank" href="<?php echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'tab_events_logger', '/events-logger/' ) ); ?>" class="button button-primary" rel="noopener">Learn more</a></p>
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

			<img src="<?php echo esc_url( WF_SN_PLUGIN_URL . 'images/firewall.jpg' ); ?>" alt="Scan Core files of WordPress" class="tabimage">

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

			<p class="fomlink"><a target="_blank" href="<?php echo esc_url( \WPSecurityNinja\Plugin\Utils::generate_sn_web_link( 'tab_firewall', '/cloud-firewall/' ) ); ?>" class="button button-primary" rel="noopener">Learn more</a></p>
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
		?>
		<div class="sncard settings-card">
			<h2><span class="dashicons dashicons-shield"></span>Malware</h2>
			<p>Scan your site for malicious code and known attack signatures.</p>
			<div class="sncard infobox">
				<div class="inner">
					<h3>Upgrade to Pro for Malware Scanner</h3>
					<p>The free version includes core security tests and scanners. Upgrade to Security Ninja Pro to unlock the Malware Scanner and keep your site clean:</p>
					<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
						<li>Scan your entire site for malicious code and known attack signatures</li>
						<li>Plugin integrity checks – detect unauthorized file changes or tampering</li>
						<li>Real-time alerts and easy-to-understand reports</li>
						<li>Schedule regular malware scans with the Scheduler</li>
						<li>Exclude paths and whitelist trusted files to reduce false positives</li>
					</ul>
					<p style="margin-top: 15px;">
						<a href="<?php echo esc_url( Utils::generate_sn_web_link( 'upgrade_tab_malware', '/pricing/' ) ); ?>" class="button button-primary button-small" target="_blank" rel="noopener">Upgrade to Pro</a>
					</p>
				</div>
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
		?>
		<div class="sncard settings-card">
			<h2><span class="dashicons dashicons-backup"></span>Scheduler</h2>
			<p>Run security scans on a schedule and receive email reports.</p>
			<div class="sncard infobox">
				<div class="inner">
					<h3>Upgrade to Pro for Scheduled Scanner</h3>
					<p>Run security checks on a schedule without lifting a finger. Upgrade to Security Ninja Pro to unlock the Scheduler:</p>
					<ul style="list-style: disc; margin-left: 20px; margin-top: 10px;">
						<li>Schedule automated scans – daily, weekly, or monthly</li>
						<li>Run Security Tests, Core Scanner, and Malware Scanner on a single schedule</li>
						<li>Receive detailed email reports with findings and recommendations</li>
						<li>Background execution so scans never time out</li>
						<li>Historical tracking of scan results over time</li>
					</ul>
					<p style="margin-top: 15px;">
						<a href="<?php echo esc_url( Utils::generate_sn_web_link( 'upgrade_tab_scheduler', '/pricing/' ) ); ?>" class="button button-primary button-small" target="_blank" rel="noopener">Upgrade to Pro</a>
					</p>
				</div>
			</div>
		</div>
		<?php
	}
}
