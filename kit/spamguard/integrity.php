<?php
/**
 * SgIntegrity - file checksum monitor + malware pattern scan for a PHP/HTML site.
 *
 *   php integrity.php baseline    remember the current files as "known good"
 *   php integrity.php check       compare + scan, e-mails notify_email if something is wrong (use in cron)
 *
 * Honest scope: this catches changed/added/removed files and common webshell/backdoor patterns.
 * It is NOT an antivirus; pattern scans can have false positives and miss clever malware.
 */

if (PHP_SAPI !== 'cli' && !defined('SG_LIB')) {
    http_response_code(403);
    exit;
}
if (!defined('SG_LIB')) {
    define('SG_LIB', true);
}
require_once __DIR__ . '/spamguard.php';

final class SgIntegrity
{
    const TRACK_EXT = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'inc', 'html', 'htm', 'js', 'htaccess', 'ini'];
    const MAX_FILES = 20000;
    const MAX_HASH_BYTES = 8388608;   // 8 MB
    const MAX_SCAN_BYTES = 2097152;   // 2 MB

    public static function root(): string
    {
        $c = SpamGuard::config();
        if ($c['scan_root'] !== '' && is_dir($c['scan_root'])) {
            return rtrim((string) realpath($c['scan_root']), '/');
        }
        return rtrim((string) realpath(dirname(__DIR__)), '/');
    }

    private static function file(string $name): ?string
    {
        $dir = SpamGuard::dataPath();
        return $dir === null ? null : $dir . '/' . $name;
    }

    /** @return array<string,array{s:int,m:int,h:string}> relative path => meta */
    private static function walk(string $root): array
    {
        $skipReal = [];
        $data = SpamGuard::dataPath();
        if ($data !== null) {
            $skipReal[] = (string) realpath($data);
        }
        $map = [];
        $it = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            function ($cur) use ($skipReal) {
                if ($cur->isLink()) {
                    return false;
                }
                if ($cur->isDir()) {
                    $n = $cur->getFilename();
                    return !in_array($n, ['.git', '.svn', 'node_modules'], true) && !in_array((string) $cur->getRealPath(), $skipReal, true);
                }
                $ext = strtolower($cur->getExtension());
                return in_array($ext, self::TRACK_EXT, true);
            }
        ), RecursiveIteratorIterator::LEAVES_ONLY);
        foreach ($it as $fi) {
            if (!$fi->isFile()) {
                continue;
            }
            if (count($map) >= self::MAX_FILES) {
                break;
            }
            $path = $fi->getPathname();
            $rel = ltrim(substr($path, strlen($root)), '/');
            $size = (int) $fi->getSize();
            $map[$rel] = [
                's' => $size,
                'm' => (int) $fi->getMTime(),
                'h' => $size <= self::MAX_HASH_BYTES ? (string) @hash_file('sha256', $path) : '',
            ];
        }
        ksort($map);
        return $map;
    }

    private static function writeJson(string $name, array $data): bool
    {
        $f = self::file($name);
        if ($f === null) {
            return false;
        }
        $tmp = $f . '.tmp' . bin2hex(random_bytes(3));
        if (@file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) === false) {
            return false;
        }
        return @rename($tmp, $f);
    }

    private static function readJson(string $name): ?array
    {
        $f = self::file($name);
        if ($f === null || !is_file($f)) {
            return null;
        }
        $j = json_decode((string) @file_get_contents($f), true);
        return is_array($j) ? $j : null;
    }

    public static function baselineInfo(): ?array
    {
        $b = self::readJson('baseline.json');
        return $b ? ['created' => (int) $b['created'], 'files' => count($b['files'])] : null;
    }

    public static function last(): ?array
    {
        return self::readJson('last-check.json');
    }

    /** Remember the current state of the site as "known good". */
    public static function baseline(): array
    {
        @set_time_limit(120);
        $files = self::walk(self::root());
        $ok = self::writeJson('baseline.json', ['created' => time(), 'files' => $files]);
        return ['ok' => $ok, 'files' => count($files)];
    }

    /** @return array<int,array{0:string,1:string}> pattern => [severity, label] */
    private static function patterns(): array
    {
        return [
            ['~eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(~i', 'high', 'eval() of an encoded payload'],
            ['~gzinflate\s*\(\s*base64_decode~i', 'high', 'gzinflate(base64_decode()) obfuscation'],
            ['~(eval|assert|system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)~i', 'high', 'executes request data as code/commands'],
            ['~preg_replace\s*\(\s*[\'"]/[^\'"]*/[a-z]*e[a-z]*[\'"]~i', 'high', 'preg_replace with /e modifier (code execution)'],
            ['~(FilesMan|c99shell|r57shell|b374k|IndoXploit|WSO\s*\d|Wso_|Mini\s*Shell|Tryag)~i', 'high', 'known webshell signature'],
            ['~base64_decode\s*\(\s*[\'"][A-Za-z0-9+/=]{200,}[\'"]~', 'high', 'large embedded base64 payload'],
            ['~\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[~', 'medium', 'variable function called with request data'],
            ['~(file_put_contents|fwrite)\s*\([^;]{0,120}\$_(GET|POST|REQUEST)~i', 'medium', 'writes files from request data'],
            ['~document\.write\s*\(\s*unescape\s*\(~i', 'medium', 'JavaScript unescape() injection'],
            ['~RewriteCond\s+%\{HTTP_(REFERER|USER_AGENT)\}[^\n]*(google|yahoo|bing|baidu)~i', 'medium', 'redirect rule aimed at search-engine visitors (common hack)'],
            ['~auto_prepend_file|auto_append_file~i', 'medium', 'auto prepend/append of a PHP file'],
            ['~<script[^>]+src=[\'"]https?://[^\'">]*\.(ru|cn|tk|xyz|top|pw)/[^\'">]*[\'"]~i', 'low', 'external script from a risky domain'],
        ];
    }

    private static function scanFile(string $abs, string $rel): array
    {
        $out = [];
        $isPhp = (bool) preg_match('~\.(php\d?|phtml|phar|inc)$~i', $rel);
        if ($isPhp && preg_match('~(^|/)(uploads?|images?|img|files|media|gallery|assets/images)(/|$)~i', $rel)) {
            $out[] = [$rel, 'high', 'PHP file inside an upload/image folder', 0];
        }
        if (preg_match('~\.(php\d?|phtml)\.[a-z0-9]{2,4}$~i', $rel)) {
            $out[] = [$rel, 'medium', 'double file extension (e.g. .php.jpg)', 0];
        }
        if (preg_match('~(^|/)(c99|r57|wso|shell|b374k|indoxploit|alfa|mini)\.php$~i', $rel)) {
            $out[] = [$rel, 'high', 'file name of a known webshell', 0];
        }
        $size = (int) @filesize($abs);
        if ($size === 0 || $size > self::MAX_SCAN_BYTES) {
            return $out;
        }
        $code = (string) @file_get_contents($abs);
        foreach (self::patterns() as $p) {
            $isHt = (bool) preg_match('~\.htaccess$~i', $rel);
            $isJs = (bool) preg_match('~\.(js|html?)$~i', $rel);
            $label = $p[2];
            if ($isHt && strpos($label, 'redirect rule') === false && strpos($label, 'auto prepend') === false) {
                continue;
            }
            if ($isJs && !$isPhp && strpos($label, 'JavaScript') === false && strpos($label, 'external script') === false) {
                continue;
            }
            if (preg_match($p[0], $code, $m, PREG_OFFSET_CAPTURE)) {
                $line = 1 + substr_count(substr($code, 0, (int) $m[0][1]), "\n");
                $out[] = [$rel, $p[1], $label, $line];
            }
        }
        if ($isPhp) {
            foreach (explode("\n", $code) as $i => $ln) {
                if (strlen($ln) > 6000 && preg_match('~(eval|base64_decode|gzinflate|\$[a-z0-9_]{1,3}\[)~i', $ln)) {
                    $out[] = [$rel, 'medium', 'extremely long obfuscated-looking line', $i + 1];
                    break;
                }
            }
        }
        return $out;
    }

    /** Compare with the baseline, scan every tracked file for malware patterns, remember the result. */
    public static function check(): array
    {
        @set_time_limit(120);
        $root = self::root();
        $now = self::walk($root);
        $base = self::readJson('baseline.json');
        $changed = $added = $removed = [];
        if ($base) {
            $old = $base['files'];
            foreach ($now as $p => $m) {
                if (!isset($old[$p])) {
                    $added[] = $p;
                } elseif ($old[$p]['h'] !== $m['h'] || $old[$p]['s'] !== $m['s']) {
                    $changed[] = $p;
                }
            }
            foreach ($old as $p => $_) {
                if (!isset($now[$p])) {
                    $removed[] = $p;
                }
            }
        }
        $findings = [];
        foreach ($now as $rel => $_) {
            foreach (self::scanFile($root . '/' . $rel, $rel) as $f) {
                $findings[] = ['path' => $f[0], 'severity' => $f[1], 'rule' => $f[2], 'line' => $f[3]];
            }
        }
        $order = ['high' => 0, 'medium' => 1, 'low' => 2];
        usort($findings, function ($a, $b) use ($order) {
            return $order[$a['severity']] <=> $order[$b['severity']];
        });
        $res = [
            'time' => time(),
            'files' => count($now),
            'has_baseline' => $base !== null,
            'baseline_at' => $base ? (int) $base['created'] : null,
            'changed' => array_slice($changed, 0, 500),
            'added' => array_slice($added, 0, 500),
            'removed' => array_slice($removed, 0, 500),
            'findings' => array_slice($findings, 0, 500),
            'high' => count(array_filter($findings, function ($f) {
                return $f['severity'] === 'high';
            })),
        ];
        self::writeJson('last-check.json', $res);
        return $res;
    }

    public static function problems(array $r): int
    {
        return count($r['changed']) + count($r['added']) + count($r['removed']) + count($r['findings']);
    }
}

// ---------------------------------------------------------------- command line (cron) mode
if (PHP_SAPI === 'cli' && isset($argv[0]) && @realpath($argv[0]) === __FILE__) {
    $cmd = $argv[1] ?? 'check';
    if ($cmd === 'baseline') {
        $r = SgIntegrity::baseline();
        echo $r['ok'] ? "Baseline saved: {$r['files']} files.\n" : "Could not save baseline (data folder not writable?).\n";
        exit($r['ok'] ? 0 : 1);
    }
    $r = SgIntegrity::check();
    $site = SpamGuard::config()['site_id'];
    $lines = ["SpamGuard integrity report for '$site' (" . date('Y-m-d H:i') . ")", "Files tracked: {$r['files']}"];
    if (!$r['has_baseline']) {
        $lines[] = 'NOTE: no baseline yet. Run "php integrity.php baseline" once the site is known to be clean.';
    }
    foreach (['changed' => 'CHANGED', 'added' => 'NEW', 'removed' => 'DELETED'] as $k => $label) {
        foreach ($r[$k] as $p) {
            $lines[] = "$label: $p";
        }
    }
    foreach ($r['findings'] as $f) {
        $lines[] = strtoupper($f['severity']) . ': ' . $f['path'] . ($f['line'] ? ':' . $f['line'] : '') . ' - ' . $f['rule'];
    }
    $text = implode("\n", $lines) . "\n";
    echo $text;
    $to = SpamGuard::config()['notify_email'];
    if ($to !== '' && SgIntegrity::problems($r) > 0) {
        @mail($to, "[SpamGuard] Files changed or suspicious code on $site", $text);
    }
    exit(SgIntegrity::problems($r) > 0 ? 1 : 0);
}
