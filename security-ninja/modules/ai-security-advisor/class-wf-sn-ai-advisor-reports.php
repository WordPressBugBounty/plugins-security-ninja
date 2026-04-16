<?php
/**
 * AI Security Advisor – reports storage (DB table) and token estimation.
 *
 * Stores each generated report in wf_sn_ai_reports. Token counts saved for analytics; not shown in UI.
 *
 * @package Security_Ninja
 */

namespace WPSecurityNinja\Plugin\AiAdvisor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Wf_Sn_Ai_Advisor_Reports
 */
class Wf_Sn_Ai_Advisor_Reports {

	const TABLE_NAME = 'wf_sn_ai_reports';

	/**
	 * Get the full table name including prefix.
	 *
	 * @return string
	 */
	public static function get_table_name() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE_NAME;
	}

	/**
	 * Create the reports table if it does not exist.
	 *
	 * @return bool True if table exists or was created.
	 */
	public static function ensure_table() {
		global $wpdb;
		$table = self::get_table_name();
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table ) {
			return true;
		}
		if ( ! function_exists( 'dbDelta' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}
		$charset = $wpdb->get_charset_collate();
		$sql     = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created datetime NOT NULL,
			report_text longtext NOT NULL,
			provider varchar(64) DEFAULT '',
			model varchar(64) DEFAULT NULL,
			token_input int unsigned NOT NULL DEFAULT 0,
			token_output int unsigned DEFAULT NULL,
			request_type varchar(32) DEFAULT 'full_report',
			PRIMARY KEY  (id),
			KEY  created (created)
		) {$charset};";
		dbDelta( $sql );
		return true;
	}

	/**
	 * Estimate input token count from system instruction + prompt text.
	 * Uses ~4 characters per token (typical for English/mixed content). Filterable for accuracy.
	 *
	 * @param string $system_instruction System instruction text.
	 * @param string $prompt_text       User/prompt text.
	 * @return int Estimated input tokens.
	 */
	public static function estimate_input_tokens( $system_instruction, $prompt_text ) {
		$total_chars = strlen( $system_instruction ) + strlen( $prompt_text );
		$estimate    = (int) ceil( $total_chars / 4 );
		return (int) apply_filters( 'wf_sn_ai_advisor_estimate_input_tokens', $estimate, $system_instruction, $prompt_text );
	}

	/**
	 * Estimate output token count from response text (when API does not return usage).
	 *
	 * @param string $response_text Response body.
	 * @return int Estimated output tokens.
	 */
	public static function estimate_output_tokens( $response_text ) {
		$estimate = (int) ceil( strlen( $response_text ) / 4 );
		return (int) apply_filters( 'wf_sn_ai_advisor_estimate_output_tokens', $estimate, $response_text );
	}

	/**
	 * Insert a report row.
	 *
	 * @param string     $report_text   Full report content.
	 * @param string     $provider      Provider id (e.g. wordpress_connectors, wp_security_ninja).
	 * @param string|null $model        Model name if applicable.
	 * @param int        $token_input   Input token count (estimated or from API).
	 * @param int|null   $token_output  Output token count (estimated or from API).
	 * @param string     $request_type  Request type (e.g. full_report).
	 * @return int|false Insert id or false on failure.
	 */
	public static function insert_report( $report_text, $provider = '', $model = null, $token_input = 0, $token_output = null, $request_type = 'full_report' ) {
		global $wpdb;
		self::ensure_table();
		$table = self::get_table_name();
		$ok    = $wpdb->insert(
			$table,
			array(
				'created'      => current_time( 'mysql' ),
				'report_text'  => $report_text,
				'provider'     => $provider,
				'model'        => $model,
				'token_input'  => max( 0, (int) $token_input ),
				'token_output' => null !== $token_output ? max( 0, (int) $token_output ) : null,
				'request_type' => $request_type,
			),
			array( '%s', '%s', '%s', '%s', '%d', '%d', '%s' )
		);
		return $ok ? (int) $wpdb->insert_id : false;
	}

	/**
	 * Get recent reports for display (e.g. previous responses list).
	 *
	 * @param int         $limit        Max rows.
	 * @param int         $offset       Offset.
	 * @param string|null $request_type If set, filter to this request_type (e.g. full_report, prompt_chip).
	 * @return array List of arrays with id, created, report_text, provider, model, token_input, token_output, request_type.
	 */
	public static function get_reports( $limit = 20, $offset = 0, $request_type = null ) {
		global $wpdb;
		$table = self::get_table_name();
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			return array();
		}
		$limit  = max( 1, min( 100, (int) $limit ) );
		$offset = max( 0, (int) $offset );

		if ( null !== $request_type && '' !== $request_type ) {
			$type = sanitize_key( (string) $request_type );
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT id, created, report_text, provider, model, token_input, token_output, request_type FROM {$table} WHERE request_type = %s ORDER BY created DESC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$type,
					$limit,
					$offset
				),
				ARRAY_A
			);
		} else {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT id, created, report_text, provider, model, token_input, token_output, request_type FROM {$table} ORDER BY created DESC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$limit,
					$offset
				),
				ARRAY_A
			);
		}
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Count rows for a request type.
	 *
	 * @param string $request_type Request type key.
	 * @return int
	 */
	public static function count_by_request_type( $request_type ) {
		global $wpdb;
		$table = self::get_table_name();
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			return 0;
		}
		$type = sanitize_key( (string) $request_type );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name internal
		$n = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE request_type = %s", $type ) );
		return (int) $n;
	}

	/**
	 * Fetch one row by id (this site's table only).
	 *
	 * @param int $id Row id.
	 * @return array<string, mixed>|null
	 */
	public static function get_row_by_id( $id ) {
		global $wpdb;
		$table = self::get_table_name();
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			return null;
		}
		$id = (int) $id;
		if ( $id <= 0 ) {
			return null;
		}
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, created, report_text, provider, model, token_input, token_output, request_type FROM {$table} WHERE id = %d LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$id
			),
			ARRAY_A
		);
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Delete one report row by id.
	 *
	 * @param int $id Row id.
	 * @return bool True if a row was deleted.
	 */
	public static function delete_report( $id ) {
		global $wpdb;
		$table = self::get_table_name();
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
			return false;
		}
		$id = (int) $id;
		if ( $id <= 0 ) {
			return false;
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$deleted = $wpdb->delete( $table, array( 'id' => $id ), array( '%d' ) );
		return false !== $deleted && $deleted > 0;
	}

	/**
	 * Two most recent full_report rows (newest first), for delta chips.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function get_latest_two_full_reports() {
		return self::get_reports( 2, 0, 'full_report' );
	}
}
