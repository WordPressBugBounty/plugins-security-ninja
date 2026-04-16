<?php
/**
 * Security test long descriptions (help HTML) for the Security Tests UI and exports.
 *
 * @package SecurityNinja
 */

namespace WPSecurityNinja\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Loads per-test help fragments from includes/sn-test-desc-fragments/{test_id}.php.
 */
class Wf_Sn_Test_Descriptions {

	/**
	 * Absolute path to fragment directory (trailing slash).
	 *
	 * @return string
	 */
	public static function fragments_dir() {
		return trailingslashit( WF_SN_PLUGIN_DIR . 'includes/sn-test-desc-fragments' );
	}

	/**
	 * Sorted list of test ids that have a fragment file.
	 *
	 * @return string[]
	 */
	public static function get_test_ids() {
		static $ids = null;
		if ( null !== $ids ) {
			return $ids;
		}
		$ids   = array();
		$dir   = self::fragments_dir();
		$files = glob( $dir . '*.php' );
		if ( ! is_array( $files ) ) {
			return $ids;
		}
		foreach ( $files as $path ) {
			$base = basename( $path, '.php' );
			if ( 'index' === $base ) {
				continue;
			}
			$key = sanitize_key( $base );
			if ( $key === $base && is_readable( $path ) && self::is_path_inside_fragments_dir( $path ) ) {
				$ids[] = $key;
			}
		}
		sort( $ids );
		return $ids;
	}

	/**
	 * Whether a real path is inside the fragments directory.
	 *
	 * @param string $file Absolute file path.
	 * @return bool
	 */
	private static function is_path_inside_fragments_dir( $file ) {
		$dir  = realpath( self::fragments_dir() );
		$real = realpath( $file );
		if ( ! $dir || ! $real ) {
			return false;
		}
		$dir = untrailingslashit( $dir );
		return ( strpos( $real, $dir . DIRECTORY_SEPARATOR ) === 0 );
	}

	/**
	 * Inner HTML for the help block (same as former .test_description contents).
	 *
	 * @param string $test_id Test slug.
	 * @return string HTML or empty if unknown.
	 */
	public static function get_description_html( $test_id ) {
		$test_id = sanitize_key( (string) $test_id );
		if ( '' === $test_id || sanitize_key( $test_id ) !== $test_id ) {
			return '';
		}
		$file = self::fragments_dir() . $test_id . '.php';
		if ( ! is_readable( $file ) || ! self::is_path_inside_fragments_dir( $file ) ) {
			return '';
		}
		ob_start();
		include $file;
		return trim( (string) ob_get_clean() );
	}

	/**
	 * Plain-text variant for AI / logs.
	 *
	 * @param string $html    Description HTML.
	 * @param string $test_id Test slug.
	 * @return string
	 */
	public static function get_plain_from_html( $html, $test_id ) {
		$plain = wp_strip_all_tags( (string) $html );
		$plain = html_entity_decode( $plain, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		$plain = preg_replace( '/\s+/u', ' ', $plain );
		$plain = trim( (string) $plain );
		/**
		 * Filter plain-text test description derived from help HTML.
		 *
		 * @param string $plain   Plain text.
		 * @param string $test_id Test id.
		 * @param string $html    Original HTML.
		 */
		return apply_filters( 'wf_sn_test_description_plain', $plain, $test_id, $html );
	}

	/**
	 * Structured guidance for AI context (Security Advisor). Uses same fragment HTML as the Tests UI.
	 *
	 * @param string $test_id Test slug.
	 * @return array{title: string, short: string, guidance: string, caveats: string, fix_hints: string}
	 */
	public static function get_guidance_for_ai( $test_id ) {
		$empty = array(
			'title'      => '',
			'short'      => '',
			'guidance'   => '',
			'caveats'    => '',
			'fix_hints'  => '',
		);
		$test_id = sanitize_key( (string) $test_id );
		if ( '' === $test_id || sanitize_key( $test_id ) !== $test_id ) {
			return $empty;
		}

		$title = '';
		if ( class_exists( __NAMESPACE__ . '\\Wf_Sn_Tests', false ) ) {
			$tests_meta = Wf_Sn_Tests::return_security_tests();
			if ( isset( $tests_meta[ $test_id ]['title'] ) && is_string( $tests_meta[ $test_id ]['title'] ) ) {
				$title = $tests_meta[ $test_id ]['title'];
			}
		}

		$html  = self::get_description_html( $test_id );
		$plain = '' !== $html ? self::get_plain_from_html( $html, $test_id ) : '';

		$short_len = (int) apply_filters( 'wf_sn_ai_test_guidance_short_length', 400, $test_id );
		$short     = '';
		if ( '' !== $plain && function_exists( 'mb_substr' ) ) {
			$short = mb_substr( $plain, 0, max( 0, $short_len ), 'UTF-8' );
			if ( mb_strlen( $plain, 'UTF-8' ) > $short_len ) {
				$short .= '…';
			}
		} elseif ( '' !== $plain ) {
			$short = substr( $plain, 0, $short_len );
		}

		$max_guidance = (int) apply_filters( 'wf_sn_ai_test_guidance_max_chars', 6000, $test_id );
		if ( $max_guidance > 0 && '' !== $plain && function_exists( 'mb_strlen' ) && mb_strlen( $plain, 'UTF-8' ) > $max_guidance ) {
			$plain = mb_substr( $plain, 0, $max_guidance, 'UTF-8' ) . ' …';
		} elseif ( $max_guidance > 0 && '' !== $plain && strlen( $plain ) > $max_guidance ) {
			$plain = substr( $plain, 0, $max_guidance ) . ' …';
		}

		return array(
			'title'     => $title,
			'short'     => $short,
			'guidance'  => $plain,
			'caveats'   => '',
			'fix_hints' => '',
		);
	}

	/**
	 * Data for Security Tests UI (titles from wf_sn_tests + html + plain).
	 *
	 * @return array<string, array{title: string, html: string, plain: string}>
	 */
	public static function get_payload_for_tests_ui() {
		if ( ! class_exists( __NAMESPACE__ . '\\Wf_Sn_Tests', false ) ) {
			return array();
		}
		$tests_meta = Wf_Sn_Tests::return_security_tests();
		$out        = array();
		foreach ( self::get_test_ids() as $tid ) {
			$html = self::get_description_html( $tid );
			if ( '' === $html ) {
				continue;
			}
			$title = '';
			if ( isset( $tests_meta[ $tid ]['title'] ) && is_string( $tests_meta[ $tid ]['title'] ) ) {
				$title = $tests_meta[ $tid ]['title'];
			}
			$out[ $tid ] = array(
				'title' => $title,
				'html'  => $html,
				'plain' => self::get_plain_from_html( $html, $tid ),
			);
		}
		return $out;
	}

	/**
	 * Export map for AI and integrations.
	 *
	 * @return array<string, array{title: string, html: string, plain: string}>
	 */
	public static function get_for_export() {
		$data = self::get_payload_for_tests_ui();
		/**
		 * Filter exported test descriptions (id => title, html, plain).
		 *
		 * @param array $data Payload.
		 */
		return apply_filters( 'wf_sn_test_descriptions_export', $data );
	}
}
