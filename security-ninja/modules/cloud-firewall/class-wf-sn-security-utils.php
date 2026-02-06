<?php
namespace WPSecurityNinja\Plugin;

/**
 * Security utilities for file operations and validation
 * 
 * @author Lars Koudal
 * @since v1.0.0
 */
class Wf_Sn_Security_Utils {
    
    /**
     * Validate file type based on extension
     * 
     * @param string $file_path Path to the file
     * @param array $allowed_extensions Array of allowed file extensions
     * @return bool True if file type is allowed
     */
    public static function validate_file_type($file_path, $allowed_extensions = array('php', 'txt', 'html', 'css', 'js')) {
        $extension = pathinfo($file_path, PATHINFO_EXTENSION);
        return in_array(strtolower($extension), $allowed_extensions);
    }
    
    /**
     * Validate file size
     * 
     * @param string $file_path Path to the file
     * @param int $max_size Maximum file size in bytes
     * @return bool True if file size is within limit
     */
    public static function validate_file_size($file_path, $max_size = 1048576) {
        $file_size = filesize($file_path);
        return $file_size !== false && $file_size <= $max_size;
    }
    
    /**
     * Validate file path is within allowed directories
     * 
     * @param string $file_path Path to the file
     * @param array $allowed_dirs Array of allowed directory paths
     * @return bool True if file is within allowed directories
     */
    public static function validate_file_path($file_path, $allowed_dirs) {
        $file_real_path = realpath($file_path);
        if ($file_real_path === false) {
            return false;
        }
        
        foreach ($allowed_dirs as $dir) {
            if (strpos($file_real_path, $dir) === 0) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Comprehensive file validation
     * 
     * @param string $file_path Path to the file
     * @param array $options Validation options
     * @return array Validation result with 'valid' boolean and 'errors' array
     */
    public static function validate_file($file_path, $options = array()) {
        $defaults = array(
            'check_readable' => true,
            'check_size' => true,
            'max_size' => 1048576, // 1MB default
            'check_type' => true,
            'allowed_extensions' => array('php', 'txt', 'html', 'css', 'js'),
            'check_mime' => false,
            'check_path' => true,
            'allowed_dirs' => array(ABSPATH)
        );
        
        $options = wp_parse_args($options, $defaults);
        $errors = array();
        
        // Check if file exists and is readable
        if ($options['check_readable'] && (!is_file($file_path) || !is_readable($file_path))) {
            $errors[] = 'File does not exist or is not readable';
        }
        
        // Check file size
        if ($options['check_size'] && !self::validate_file_size($file_path, $options['max_size'])) {
            $errors[] = 'File size exceeds limit';
        }
        
        // Check file type
        if ($options['check_type'] && !self::validate_file_type($file_path, $options['allowed_extensions'])) {
            $errors[] = 'File type not allowed';
        }
        
        // Check MIME type (optional)
        if ($options['check_mime']) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime_type = finfo_file($finfo, $file_path);
            finfo_close($finfo);
            
            $allowed_mimes = array('text/plain', 'text/html', 'text/css', 'application/javascript', 'application/x-httpd-php');
            if (!in_array($mime_type, $allowed_mimes)) {
                $errors[] = 'MIME type not allowed';
            }
        }
        
        // Check file path
        if ($options['check_path'] && !self::validate_file_path($file_path, $options['allowed_dirs'])) {
            $errors[] = 'File path not allowed';
        }
        
        return array(
            'valid' => empty($errors),
            'errors' => $errors
        );
    }
    
    /**
     * Secure file_get_contents with validation
     * 
     * @param string $file_path Path to the file
     * @param array $options Validation options
     * @return string|false File contents or false on failure
     */
    public static function secure_file_get_contents($file_path, $options = array()) {
        $validation = self::validate_file($file_path, $options);
        
        if (!$validation['valid']) {
            return false;
        }
        
        return file_get_contents($file_path);
    }
}
