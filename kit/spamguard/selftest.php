<?php
/**
 * Setup checker. Browser: /spamguard/selftest.php?key=<selftest key printed by make-config>
 * Command line: php selftest.php.  Delete this file once setup is done.
 */
require __DIR__ . '/spamguard.php';

$cli = PHP_SAPI === 'cli';
$cfg = SpamGuard::config();
if (!$cli) {
    $key = (string) ($_GET['key'] ?? '');
    if ($cfg['selftest_key'] === '' || !hash_equals($cfg['selftest_key'], $key)) {
        http_response_code(403);
        exit('Forbidden');
    }
    header('Content-Type: text/plain; charset=utf-8');
    header('X-Robots-Tag: noindex');
}

$rows = [];
$check = function (string $name, bool $ok, string $note = '') use (&$rows) {
    $rows[] = [$ok, $name, $note];
};

$check('PHP version 7.4 or newer', version_compare(PHP_VERSION, '7.4.0', '>='), PHP_VERSION);
$check('config.php present with a secret key', $cfg['secret'] !== '', 'run: php make-config.php');
$check('admin password set', $cfg['admin_password_hash'] !== '');
$check('pdo_sqlite available (history, rate limit, admin page)', extension_loaded('pdo_sqlite'), 'ask your host to enable pdo_sqlite');
$dir = SpamGuard::dataPath();
$check('data folder writable', $dir !== null, (string) $cfg['data_dir']);
$check('database opens', SpamGuard::pdo() !== null);
$check('mbstring (better text handling)', function_exists('mb_strlen'), 'optional');
$check('curl or allow_url_fopen (only needed for Turnstile)', function_exists('curl_init') || (bool) ini_get('allow_url_fopen'), 'optional');
$check('mail() available (integrity alerts)', function_exists('mail'), 'optional');
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
$check('page served over HTTPS', $cli || $https, 'use HTTPS for the admin page');
if ($dir !== null) {
    $ex = @file_exists($dir . '/.htaccess');
    $check('data folder protected by .htaccess', $ex, 'on nginx hosts keep data_dir outside the web root');
}
$ok = true;
foreach ($rows as $r) {
    echo ($r[0] ? '[ OK ] ' : '[FAIL] ') . $r[1] . ($r[2] !== '' ? '  - ' . $r[2] : '') . "\n";
    if (!$r[0] && strpos($r[2], 'optional') === false) {
        $ok = false;
    }
}
echo $ok ? "\nAll required checks passed.\n" : "\nFix the [FAIL] items above, then reload.\n";
