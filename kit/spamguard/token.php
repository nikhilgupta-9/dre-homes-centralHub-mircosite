<?php
// Hands out a fresh signed time-token to the form's JavaScript. Output: {"t":"..."}
require __DIR__ . '/spamguard.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, max-age=0');
header('X-Robots-Tag: noindex');

$t = '';
try {
    if (SpamGuard::config()['secret'] !== '') {
        $t = SpamGuard::makeToken();
    }
} catch (\Throwable $e) {
    $t = '';
}
echo json_encode(['t' => $t]);

// Page views double as the hub's heartbeat clock (no cron needed). Costs one filemtime() when nothing is due.
if (class_exists('SgHub', false)) {
    SgHub::schedule(false);
}
