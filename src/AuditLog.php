<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use Throwable;

/**
 * Lightweight activity log for the plugin, backed by glpi_plugin_nessusglpi_logs.
 * Writing must never throw — auditing an action must not be able to break that action.
 */
class AuditLog
{
    public const TABLE = 'glpi_plugin_nessusglpi_logs';

    public const LEVEL_INFO    = 'info';
    public const LEVEL_WARNING = 'warning';
    public const LEVEL_ERROR   = 'error';

    public static function getTable(): string
    {
        return self::TABLE;
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function record(string $level, string $context, string $message, array $payload = []): void
    {
        global $DB;

        if (!isset($DB) || !is_object($DB)) {
            return;
        }

        if (!in_array($level, [self::LEVEL_INFO, self::LEVEL_WARNING, self::LEVEL_ERROR], true)) {
            $level = self::LEVEL_INFO;
        }

        $encodedPayload = null;
        if ($payload !== []) {
            $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $encodedPayload = is_string($json) ? $json : null;
        }

        try {
            $DB->insert(self::getTable(), [
                'level'         => $level,
                'context'       => mb_substr($context, 0, 64),
                'message'       => $message,
                'payload'       => $encodedPayload,
                'date_creation' => date('Y-m-d H:i:s'),
            ]);
        } catch (Throwable $e) {
            // Intentionally swallowed: auditing is best-effort.
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function info(string $context, string $message, array $payload = []): void
    {
        self::record(self::LEVEL_INFO, $context, $message, $payload);
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function warning(string $context, string $message, array $payload = []): void
    {
        self::record(self::LEVEL_WARNING, $context, $message, $payload);
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function error(string $context, string $message, array $payload = []): void
    {
        self::record(self::LEVEL_ERROR, $context, $message, $payload);
    }
}
