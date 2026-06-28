<?php

declare(strict_types=1);

/**
 * Dependency-free test runner for environments without PHPUnit installed (e.g. the GLPI
 * production image). Provides a tiny TestCase polyfill, then runs every test* method of the
 * suite. In a dev environment with real PHPUnit, run `vendor/bin/phpunit` instead.
 *
 * Usage: php tests/run.php
 */

namespace PHPUnit\Framework {
    if (!class_exists(TestCase::class, false)) {
        class TestCase
        {
            public function assertSame($expected, $actual, string $message = ''): void
            {
                if ($expected !== $actual) {
                    throw new \RuntimeException(sprintf(
                        'assertSame failed %s: expected %s, got %s',
                        $message,
                        var_export($expected, true),
                        var_export($actual, true)
                    ));
                }
            }

            public function assertStringContainsString(string $needle, string $haystack, string $message = ''): void
            {
                if (!str_contains($haystack, $needle)) {
                    throw new \RuntimeException(sprintf("assertStringContainsString failed %s: '%s' not found", $message, $needle));
                }
            }

            public function assertStringNotContainsString(string $needle, string $haystack, string $message = ''): void
            {
                if (str_contains($haystack, $needle)) {
                    throw new \RuntimeException(sprintf("assertStringNotContainsString failed %s: '%s' was present", $message, $needle));
                }
            }

            public function assertTrue($condition, string $message = ''): void
            {
                if ($condition !== true) {
                    throw new \RuntimeException('assertTrue failed ' . $message);
                }
            }
        }
    }
}

namespace {
    require __DIR__ . '/bootstrap.php';
    require __DIR__ . '/TicketServiceTest.php';

    $testClass = \GlpiPlugin\Nessusglpi\Tests\TicketServiceTest::class;
    $methods = array_filter(
        get_class_methods($testClass),
        static fn (string $m): bool => str_starts_with($m, 'test')
    );

    $pass = 0;
    $fail = 0;
    $failures = [];

    foreach ($methods as $method) {
        $instance = new $testClass();
        try {
            $instance->$method();
            $pass++;
            fwrite(STDOUT, "PASS  {$method}\n");
        } catch (\Throwable $e) {
            $fail++;
            $failures[] = "{$method}: " . $e->getMessage();
            fwrite(STDOUT, "FAIL  {$method}\n");
        }
    }

    fwrite(STDOUT, "\n" . str_repeat('-', 56) . "\n");
    fwrite(STDOUT, sprintf("TicketService: %d passed, %d failed\n", $pass, $fail));
    foreach ($failures as $failure) {
        fwrite(STDOUT, "  - {$failure}\n");
    }

    exit($fail === 0 ? 0 : 1);
}
