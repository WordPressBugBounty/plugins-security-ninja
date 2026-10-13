<?php
/**
 * Shared 8G-style firewall rule patterns (no WordPress dependency).
 *
 * @package Security_Ninja
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'SECNIN_WAF_BOOTSTRAP' ) ) {
	exit;
}

return array(
	'request_uri' => array(
		'3commas'             => ',{3,}', // Matches three or more commas
				'7_or_more_hyphens'   => '-{7,}', // Matches seven or more hyphens
				'caret_backtick'      => '[\^`<>\\|]', // Matches caret, backtick, less than, greater than, backslash, or pipe characters
				'alnum_long'          => '[a-z0-9]{2000,}', // Matches any string with 2000 or more alphanumeric characters
				'eq_backslash'        => '=?\\\\(\'|%27)/?\\.', // Matches = followed optionally by a backslash or single quote and a dot
				'special_chars'       => '/(\*|"|\'|\.|,|&|&amp;?)/?$', // Matches / followed by *, ", ', ., ,, &, optionally &amp;, and optionally ending with /
				'php_file'            => '\.(php)(\()?([0-9]+)(\))?(/)?$', // Matches .php optionally followed by (), a number, and optionally ending with /
				'header_cookie'       => '/(.*)(header:|set-cookie:)(.*)=', // Matches any string containing header: or set-cookie: followed by =
				'ftp_config_files'    => '\.(s?ftp-?)config|(s?ftp-?)config\.', // Matches .config or config. with optional sftp- prefix
				'file_editors'        => '/(f?ckfinder|fck/|f?ckeditor|fullclick)', // Matches paths related to file editors or ckfinder
				'download_framework'  => '/((force-)?download|framework/main)(\.php)', // Matches specific PHP files or paths indicating file download or framework access
				'misc_chars'          => '\{0\}|"0"="0|/\(/\|\.\.\.|\+\+\+|\\\\"', // Matches {0}, "0"="0, /(/, ..., +++, or \"
				'vbulletin'           => '/(vbull(etin)?|boards|vbforum|vbweb|webvb)(/)?', // Matches paths related to vBulletin or similar forum software
				'permalink'           => '(\.|20)(get|the)(_)(permalink|posts_page_url)\(', // Matches specific patterns that could indicate an attempt to exploit or probe
				'complex_injections'  => '///|\?\?|/&&|/\*(.*)\*/|/:/|\\\\|0x00|%00|%0d%0a', // Matches sequences that could be part of complex injections
				'alfa_cgi'            => '(/)(cgi_?)?alfa(_?cgiapi|_?data|_?v[0-9]+)?(\\.php)', // Matches specific CGI or PHP files with "alfa" in the name
				'thumbnail_php'       => '(thumbs?(_editor|open)?|tim(thumbs?)?)((\\.|%2e)php)', // Matches thumbnail editor or opener PHP files
				'admin_php'           => '(/)((boot)?_?admin(er|istrator|s)(_events)?)(\\.php)', // Matches admin-related PHP files with optional prefixes
				'sensitive_user_dirs' => '(/%7e)(root|ftp|bin|nobody|named|guest|logs|sshd)(/)', // Matches user directories for sensitive usernames
				'backup_files'        => '(archive|backup|db|master|sql|wp|www|wwwroot)\\.(gz|zip)', // Matches backup or archive files
				'shell_scripts'       => '(/)(\\.?mad|alpha|c99|php|web)?sh(3|e)ll([0-9]+|\\w)(\\.php)', // Matches shell scripts, including common names and versions
				'upload_scripts'      => '(/)(admin-?|file-?)(upload)(bg|_?file|ify|svu|ye)?(\\.php)', // Matches various upload handler scripts
				'sensitive_dirs'      => '(/)(etc|var)(/)(hidden|secret|shadow|ninja|passwd|tmp)(/)?', // Matches paths attempting to access sensitive directories
				'url_manipulation'    => '(s)?(ftp|inurl|php)(s)?(:(/|%2f|%u2215)(/|%2f|%u2215))', // Matches attempts to access or manipulate URLs
				'query_manipulation'  => '(/)(=|\\$&?|&?(pws|rk)=0|_mm|_vti_|cgi(\\.|-)?|(=|/|;|,)nt\\.)', // Matches various query string manipulations and CGI invocations
				'sensitive_files'     => '(\\.)(ds_store|htaccess|htpasswd|init?|mysql-select-db)(/)?', // Matches attempts to access sensitive server files
				'bin_commands'        => '(/)(bin)(/)(cc|chmod|chsh|cpp|echo|id|kill|mail|nasm|perl|ping|ps|python|tclsh)(/)?', // Matches commands that should not be accessible via URL
				'obfuscated_js'       => '(/)?j(\\s+)?a(\\s+)?v(\\s+)?a(\\s+)?s(\\s+)?c(\\s+)?r(\\s+)?i(\\s+)?p(\\s+)?t(\\s+)?(%3a|:)', // Matches obfuscated JavaScript
				'server_dirs'         => '(/)(filemanager|htdocs|httpdocs|https?|mailman|mailto|msoffice|undefined|usage|var|vhosts|webmaster|www)(/)', // Matches common server directories or services
				'injection_attempts'  => '(\\(null\\)|\\{\\$itemURL\\}|cast\\(0x|echo(.*)kae|etc/passwd|eval\\(|null(.*)null|open_basedir|self/environ|\\+union\\+all\\+select)', // Matches various injection or exploit attempts
				'config_files'        => '(/)(db-?|j-?|my(sql)?-?|setup-?|web-?|wp-?)?(admin-?)?(setup-?)?(conf\\b|conf(ig)?)(uration)?(\\.?bak|\\.inc)?(\\.inc|\\.old|\\.php|\\.txt)', // Matches configuration or setup files
				'exploit_paths'       => '(/)((.*)crlf-?injection|(.*)xss-?protection|__(inc|jsc)|administrator|author-panel|cgi-bin|database|downloader|(db|mysql)-?admin)(/)', // Matches common admin or exploit paths
				'malicious_php'       => '(/)(haders|head|helpear|incahe|includes?|indo(sec)?|infos?|install|ioptimizes?|jmail|js|king|kiss|kodox|kro|legion|libsoft)(\\.php)', // Matches potentially malicious or sensitive PHP scripts
				'info_leak_paths'     => '(/)(awstats|document_root|dologin\\.action|error.log|extension/ext|htaccess\\.|lib/php|listinfo|phpunit/php|remoteview|server/php|www\\.root\\.)', // Matches server management or info leak paths
				'code_execution'      => '(base64_(en|de)code|benchmark|curl_exec|e?chr|eval\(|function|fwrite|(f|p)open|html|leak|passthru|p?fsockopen|phpinfo)(.*)(\\(|%28)(.*)(\\)|%29)', // Matches code execution or info leak functions
				'process_management'  => '(posix_(kill|mkfifo|setpgid|setsid|setuid)|(child|proc)_(close|get_status|nice|open|terminate)|(shell_)?exec|system)(.*)(\\(|%28)(.*)(\\)|%29)', // Matches commands or functions that manage processes or execute commands
				'remote_admin_tools'  => '(/)((c99|php|web)?shell|crossdomain|fileditor|locus7|nstview|php(get|remoteview|writer)|r57|remview|sshphp|storm7|webadmin)(.*)(\\.|%2e|\\(|%28)', // Matches shells or remote admin tools
				'wp_paths'            => '/((wp-)((201\\d|202\\d|[0-9]{2})|ad|admin(fx|rss|setup)|booking|confirm|crons|data|file|mail|one|plugins?|readindex|reset|setups?|story))(\\.php)', // Matches WordPress-specific paths
				'various_php'         => '(/)(^$|-|\\!|\\w|\\.(.*)|100|123|([^iI])?ndex|index\\.php/index|7yn|90sec|aill|ajs\\.delivery|al277|alexuse?|ali|allwrite)(\\.php)', // Matches various PHP scripts or obfuscated paths
				'site_management'     => '(/)(analyser|apache|apikey|apismtp|authenticat(e|ing)|autoload_classmap|backup(_index)?|bakup|bkht|black|bogel|bookmark|bypass|cachee?)(\\.php)', // Matches scripts related to site management or exploits
				'cleanup_scripts'     => '(/)(clean|cm(d|s)|con|connector\\.minimal|contexmini|contral|curl(test)?|data(base)?|db|db-cache|db-safe-mode|defau11|defau1t|dompdf|dst)(\\.php)', // Matches database, cleanup, or testing scripts
				'exploit_scripts'     => '(/)(elements|emails?|error.log|ecscache|edit-form|eval-stdin|export|evil|fbrrchive|filemga|filenetworks?|f0x|gank(\\.php)?|gass|gel|guide)(\\.php)', // Matches various scripts that could be used for exploits or management
				'custom_scripts'      => '(/)(logo_img|lufix|mage|marg|mass|mide|moon|mssqli|mybak|myshe|mysql|mytag_js?|nasgor|newfile|news|nf_?tracking|nginx|ngoi|ohayo|old-?index)(\\.php)', // Matches scripts that could indicate custom or exploit functionality
				'diagnostic_scripts'  => '(/)(olux|owl|pekok|petx|php-?info|phpping|popup-pomo|priv|r3x|radio|rahma|randominit|readindex|readmy|reads|repair-?bak|robot(s\\.txt)?|root)(\\.php)', // Matches diagnostic, exploit, or specific functionality scripts
				'system_control'      => '(/)(router|savepng|semayan|shell|shootme|sky|socket(c|i|iasrgasf)ontrol|sql(bak|_?dump)?|sym403|sys|system_log|tmp-?(uploads)?)(\\.php)', // Matches testing, system control, or potential exploit scripts
				'admin_tools'         => '(/)(traffic-advice|u2p|udd|ukauka|up__uzegp|up14|upa?|upxx?|vega|vip|vu(ln)?(\\w)?|webroot|weki|wikindex|wp_logns?|wp_wrong_datlib)(\\.php)', // Matches various specific or general scripts and admin tools
				'cms_scripts'         => '(/)((wp-?)?install(ation)?|wp(3|4|5|6)|wpfootes|wpzip|ws0|wsdl|wso(\\w)?|www|(uploads|wp-admin)?xleet(-shell)?|xmlsrpc|xup|xxu|zibi|zipy)(\\.php)', // Matches WordPress and other CMS related scripts or tools
				'malware_signatures'  => '(bkv74|cachedsimilar|core-stab|crgrvnkb|ctivrc|deadcode|deathshop|e7xue|eqxafaj90zir|exploits|ffmkpcal|filellli7|(fox|sid)wso|gel4y|goog1es|gvqqpinc)', // removed dkiz as it is too common
				'common_exploits'     => '(@md5|00\\.temp00|0byte|0d4y|0xor|wso1337|1h6j5|40dd1d|4price|70bex?|a57bze893|abbrevsprl|abruzi|adminer|aqbmkwwx|archivarix|beez5|bgvzc29)', // removed 'backdoor' as it is too common '0day', '3XP' also
				'exploit_keywords'    => '(handler_to_code|hax(0|o)r|hmei7|hnap1|home_url=|ibqyiove|icxbsx|indoxploi|jahat|jijle3|kcrew|laobiao|lock360|mod_(aratic|ariimag))', // removed longdog and keywordspy as they are too common and marijuan
				'exploit_tools'       => '(mobiquo|muiebl|nessus|osbxamip|priv8|qcmpecgy|r3vn330|racrew|raiz0|reportserver|r00t|respectmus|rom2823|roseleif|sh3ll|site((.){0,2})copier|sqlpatch|sux0r)', // removed phpunit
				'exploit_signatures'  => '(sym403|telerik|uddatasql|utchiha|visualfrontend|w0rm|wangdafa|wpyii2|wsoyanzo|x5cv|xattack|xbaner|xertive|xiaolei|xltavrat|xorz|xsamxad|xsvip|xxxs?s?|zabbix|zebda)',
	),
	'query_string' => array(
		'start_hyphen'           => '^(-|%2d)[^=]+$', // Matches strings that start with a hyphen or its encoding, without an equals sign following.
				'long_alnum'             => '[a-z0-9]{4000,}', // Matches any alphanumeric string longer than 4000 characters.
				'url_obfuscate'          => '(/|%2f)(:|%3a)(/|%2f)', // Matches sequences attempting to simulate or obfuscate forward slashes and colons, commonly used in URLs.
				'sensitive_files'        => 'etc/(hosts|motd|shadow)', // Matches attempts to access sensitive system files.
				'sql_injection_order'    => 'order(\s|%20)by(\s|%20)1--', // Matches SQL injection attempts that use ORDER BY clauses.
				'union_all_select'       => '\\+union\\+all\\+select', // Same payload as request_uri injection_attempts; query is no longer scanned as a path.
				'asterisk_injection'     => '(/|%2f)(\*|%2a)(\*|%2a)(/|%2f)', // Matches sequences of asterisks surrounded by slashes, potentially indicating comment injection or bypass attempts.
				'special_chars'          => '(`|<|>|\\^|\\||0x00|%00|%0d%0a)', // Matches attempts to use special characters or encoded null bytes and line terminators.
				'file_tools'             => '(f?ckfinder|f?ckeditor|fullclick)', // Matches common file upload and management tools that might be targeted for exploitation.
				'header_manipulation'    => '((.*)header:|(.*)set-cookie:(.*)=)', // Matches manipulation attempts of HTTP headers.
				'local_ip'               => '(localhost|127(\\.|%2e)0(\\.|%2e)0(\\.|%2e)1)', // Matches local IP addresses, potentially indicating SSRF attacks.
				'cmd_injection'          => '(cmd|command)(=|%3d)(chdir|mkdir)(.*)(x20)', // Matches command injection attempts.
				'php_globals'            => '(^|&)(globals|mosconfig[a-z_]{1,22}|request)(=|\\[)', // Matches attempts to manipulate PHP globals or Joomla configuration globals.
				'wp_config_access'       => '(/|%2f)((wp-)?config)((\\.|%2e)inc)?((\\.|%2e)php)', // Matches attempts to access WordPress or other configuration files.
				'thumb_exploit'          => '(thumbs?(_editor|open)?|tim(thumbs?)?)((\\.|%2e)php)', // Matches attempts to exploit thumb generator scripts.
				'dir_path_manipulation'  => '(absolute_|base|root_)(dir|path)(=|%3d)(ftp|https?)', // Matches attempts to manipulate PHP directory or path settings.
				'url_injection'          => '(s)?(ftp|inurl|php)(s)?(:(/|%2f|%u2215)(/|%2f|%u2215))', // Matches attempts to inject FTP or PHP URLs.
				'wp_permalink_injection' => '(\\.|20)(get|the)(_|%5f)(permalink|posts_page_url)(\\(|%28)', // Matches complex injection attempts, potentially targeting WordPress permalink structure.
				'critical_file_access'   => '((boot|win)((\\.|%2e)ini)|etc(/|%2f)passwd|self(/|%2f)environ)', // Matches attempts to access critical system files or environment paths.
				'path_traversal'         => '(((/|%2f){3,})|((\\.|%2e){3,})|((\\.|%2e){2,})(/|%2f|%u2215))', // Matches path traversal attempts with excessive slashes or dots.
				'code_exec_injection'    => '(benchmark|char|exec|fopen|function|html)(.*)(\\(|%28)(.*)(\\)|%29)', // Matches code execution or injection attempts.
				'php_object_injection'   => '(php)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', // Matches PHP object injection attempts.
				'eval_injection'         => '(e|%65|%45)(v|%76|%56)(a|%61|%31)(l|%6c|%4c)(.*)(\\(|%28)(.*)(\\)|%29)', // Matches eval function attempts with various encodings.
				'various_injections'     => '(/|%2f)(=|%3d|$&|_mm|cgi(\\.|\\-)|inurl(:|%3a)(/|%2f)|(mod|path)(=|%3d)(\\.|%2e))', // Matches various injection or manipulation attempts.
				'html_embed'             => '(<|%3c)(.*)(e|%65|%45)(m|%6d|%4d)(b|%62|%42)(e|%65|%45)(d|%64|%44)(.*)(>|%3e)', // Matches embedded HTML or scripts
				'iframe_injection'       => '(<|%3c)(.*)(i|%69|%49)(f|%66|%46)(r|%72|%52)(a|%61|%41)(m|%6d|%4d)(e|%65|%45)(.*)(>|%3e)', // Matches iframe injections
				'object_injection'       => '(<|%3c)(.*)(o|%4f|%6f)(b|%62|%42)(j|%4a|%6a)(e|%65|%45)(c|%63|%43)(t|%74|%54)(.*)(>|%3e)', // Matches object tag injections
				'script_injection'       => '(<|%3c)(.*)(s|%73|%53)(c|%63|%43)(r|%72|%52)(i|%69|%49)(p|%70|%50)(t|%74|%54)(.*)(>|%3e)', // Matches script tag injections
				'space_delete'           => '(\\+|%2b|%20)(d|%64|%44)(e|%65|%45)(l|%6c|%4c)(e|%65|%45)(t|%74|%54)(e|%65|%45)(\\+|%2b|%20)', // Matches space or encoded space followed by 'delete'
				'space_insert'           => '(\\+|%2b|%20)(i|%69|%49)(n|%6e|%4e)(s|%73|%53)(e|%65|%45)(r|%72|%52)(t|%74|%54)(\\+|%2b|%20)', // Matches space or encoded space followed by 'insert'
				'space_select'           => '(\\+|%2b|%20)(s|%73|%53)(e|%65|%45)(l|%6c|%4c)(e|%65|%45)(c|%63|%43)(t|%74|%54)(\\+|%2b|%20)', // Matches space or encoded space followed by 'select'
				'space_update'           => '(\\+|%2b|%20)(u|%75|%55)(p|%70|%50)(d|%64|%44)(a|%61|%41)(t|%74|%54)(e|%65|%45)(\\+|%2b|%20)', // Matches space or encoded space followed by 'update'
				'sql_null_byte'          => '(\\\\x00|(\"|%22|\'|%27)?0(\"|%22|\'|%27)?(=|%3d)(\"|%22|\'|%27)?0|cast(\\(|%28)0x|or%201(=|%3d)1)', // Matches null byte, zero equals zero, or SQL 'or 1=1' pattern
				'php_globals_access'     => '(^|&)(g|%67|%47)(l|%6c|%4c)(o|%6f|%4f)(b|%62|%42)(a|%61|%41)(l|%6c|%4c)(s|%73|%53)(=|\\[|%[0-9A-Z]{0,2})', // Matches attempts to access or manipulate PHP globals
				'request_array_access'   => '(_|%5f)(r|%72|%52)(e|%65|%45)(q|%71|%51)(u|%75|%55)(e|%65|%45)(s|%73|%53)(t|%74|%54)(=|\\[|%[0-9A-Z]{2,})', // Matches attempts to access or manipulate the request array
				'js_protocol_injection'  => '(j|%6a|%4a)(a|%61|%41)(v|%76|%56)(a|%61|%31)(s|%73|%53)(c|%63|%43)(r|%72|%52)(i|%69|%49)(p|%70|%50)(t|%74|%54)(:|%3a)(.*)(;|%3b|\\)|%29)', // Matches javascript protocol injection
				'base64_encode_attempt'  => '(b|%62|%42)(a|%61|%41)(s|%73|%53)(e|%65|%45)(6|%36)(4|%34)(_|%5f)(d|%64|%44)(e|%65|%45|n|%6e|%4e)(c|%63|%43)(o|%6f|%4f)(d|%64|%44)(e|%65|%45)(.*)(\\()(.*)(\\))', // Matches base64 encode function attempts
	),
	'user_agent' => array(
		'ua_long_alnum'       => '[a-z0-9]{2000,}', // Matches user agents longer than 2000 alphanumeric characters.
				'ua_encoded_entities' => '(&lt;|%0a|%0d|%27|%3c|%3e|%00|0x00|\\\x22)', // Matches specific encoded entities and characters often used in injection attacks.
				'ua_scraping_tools'   => '(curl|libwww-perl|pycurl|scan)', // Matches a list of common scraping and automation user agents. - note removed ahrefs and archiver
				'ua_malicious_tools'  => '(oppo\\sa33|(c99|php|web)shell|site((.){0,2})copier)', // Matches known malicious or automated tools user agents.
				'ua_command_exec'     => '(base64_decode|bin/bash|disconnect|eval|unserializ)', // Matches patterns indicative of command execution or deserialization attempts.
				'ua_bots_1'           => '(acapbot|acoonbot|alexibot|asterias|attackbot|awario|backdor|becomebot|binlar|blackwidow|blekkobot|blex|blowfish|bullseye|bunnys|butterfly|careerbot|casper)',
				'ua_bots_2'           => '(checkpriv|cheesebot|cherrypick|chinaclaw|choppy|clshttp|cmsworld|copernic|copyrightcheck|cosmos|crescent|datacha|\\bdemon\\b|diavol|discobot|dittospyder)',
				'ua_bots_3'           => '(dotbot|dotnetdotcom|dumbot|econtext|emailcollector|emailsiphon|emailwolf|eolasbot|eventures|extract|eyenetie|feedfinder|flaming|flashget|flicky|foobot|fuck)',
				'ua_bots_4'           => '(g00g1e|getright|gigabot|go-ahead-got|gozilla|grabnet|grafula|harvest|heritrix|httracks?|icarus6j|jetbot|jetcar|jikespider|kmccrew|leechftp|libweb|liebaofast)',
				'ua_bots_5'           => '(linkscan|linkwalker|loader|lwp-download|majestic|masscan|miner|mechanize|mj12bot|morfeus|moveoverbot|netmechanic|netspider|nicerspro|nikto|nominet|nutch)',
				'ua_bots_6'           => '(octopus|pagegrabber|petalbot|planetwork|postrank|proximic|purebot|queryn|queryseeker|radian6|radiation|realdownload|remoteview|rogerbot|scan|scooter|seekerspid)',
				'ua_bots_7'           => '(semalt|siclab|sindice|sistrix|sitebot|siteexplorer|sitesnagger|skygrid|smartdownload|snoopy|sosospider|spankbot|spbot|sqlmap|stackrambler|stripper|sucker|surftbot)',
				'ua_bots_8'           => '(sux0r|suzukacz|suzuran|takeout|telesoft|true_robots|turingos|turnit|vampire|vikspider|voideye|webleacher|webreaper|webstripper|webvac|webviewer|webwhacker)',
				'ua_bots_9'           => '(winhttp|wwwoffle|woxbot|xaldon|xxxyy|yamanalab|yioopbot|youda|zeus|zmeu|zune|zyborg)', // Matches various known bots, crawlers, and potentially harmful automated agents.
	),
	'referrer' => array(
		'ref_100dollars'      => '100dollars',
				'ref_unlink'          => '@unlink',
				'ref_assert'          => 'assert\(',
				'ref_best_seo'        => 'best-seo',
				'ref_blue_pill'       => 'blue\s?pill',
				'ref_cocaine'         => 'cocaine',
				'ref_ejaculat'        => 'ejaculat',
				'ref_erectile'        => 'erectile',
				'ref_erections'       => 'erections',
				'ref_hoodia'          => 'hoodia',
				'ref_huronriveracres' => 'huronriveracres',
				'ref_impotence'       => 'impotence',
				'ref_levitra'         => 'levitra',
				'ref_libido'          => 'libido',
				'ref_lipitor'         => 'lipitor',
				'ref_mopub'           => 'mopub\.com',
				'ref_order_by'        => 'order(\s|%20)by(\s|%20)1--',
				'ref_phentermin'      => 'phentermin',
				'ref_pornhelm'        => 'pornhelm',
				'ref_print_r'         => 'print_r\(',
				'ref_prozac'          => 'pro[sz]ac',
				'ref_sandyauer'       => 'sandyauer',
				'ref_semalt'          => 'semalt\.com',
				'ref_social_buttons'  => 'social-buttions',
				'ref_todaperfeita'    => 'todaperfeita',
				'ref_tramadol'        => 'tramadol',
				'ref_troyhamby'       => 'troyhamby',
				'ref_ultram'          => 'ultram',
				'ref_unicauca'        => 'unicauca',
				'ref_valium'          => 'valium',
				'ref_viagra'          => 'viagra',
				'ref_vicodin'         => 'vicodin',
				'ref_x00'             => 'x00',
				'ref_xanax'           => 'xanax',
				'ref_xbshell'         => 'xbshell',
				'ref_ypxaieo'         => 'ypxaieo',
	),
);
