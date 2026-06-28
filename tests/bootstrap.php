<?php

declare(strict_types=1);

/**
 * Test bootstrap: provides the minimal GLPI i18n shims the pure TicketService helpers need,
 * then loads the class under test. No GLPI runtime or database is required for these tests.
 */

if (!function_exists('__')) {
    function __($string, $domain = '')
    {
        return $string;
    }
}

if (!function_exists('_n')) {
    function _n($singular, $plural, $number, $domain = '')
    {
        return ((int) $number === 1) ? $singular : $plural;
    }
}

if (!function_exists('_x')) {
    function _x($context, $string, $domain = '')
    {
        return $string;
    }
}

if (!function_exists('_sx')) {
    function _sx($context, $string, $domain = '')
    {
        return $string;
    }
}

if (!function_exists('_sn')) {
    function _sn($singular, $plural, $number, $domain = '')
    {
        return ((int) $number === 1) ? $singular : $plural;
    }
}

require_once dirname(__DIR__) . '/src/TicketService.php';
