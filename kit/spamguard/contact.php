<?php
// Public: the site's current contact details as JSON (used by contact.js). Pushed here by the central hub.
require __DIR__ . '/spamguard.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: public, max-age=300');
header('X-Content-Type-Options: nosniff');

$out = ['v' => 0];
try {
    $c = class_exists('SgHub', false) ? SgHub::readSynced('contact.json') : null;
    if ($c && isset($c['v'])) {
        $out = ['v' => (int) $c['v'], 'f' => (object) ($c['f'] ?? []), 'custom' => (object) ($c['custom'] ?? []), 'legacy' => (object) ($c['legacy'] ?? [])];
    }
} catch (\Throwable $e) {
}
echo json_encode($out, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

// every page view that loads contact.js also drives the hub sync clock (no cron needed)
if (class_exists('SgHub', false)) {
    SgHub::schedule(false);
}
