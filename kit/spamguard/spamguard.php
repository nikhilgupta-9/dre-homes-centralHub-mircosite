<?php
/**
 * SpamGuard v1.0 - standalone anti-spam for PHP enquiry / contact forms.
 *
 * - PHP 7.4+ (written for shared hosting, no Composer, no MySQL needed)
 * - Storage: SQLite (PDO) inside a protected data folder
 * - FAIL-OPEN: if anything inside SpamGuard breaks, the form still works.
 *
 * Use in any form handler (first lines):
 *     require_once __DIR__ . '/spamguard/spamguard.php';
 *     SpamGuard::guard();
 * After that line only real/suspicious enquiries reach your old code.
 */

// This file is a library: never run it directly from the browser.
if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME']) && @realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    http_response_code(403);
    exit;
}
// (A `class_exists() => return` guard cannot work here: PHP declares the class below before any code runs.
//  Use require_once, as the README says.)

if (is_file(__DIR__ . '/hub-client.php')) {
    require_once __DIR__ . '/hub-client.php';
}

final class SpamGuard
{
    const VERSION = '1.4.0';
    const F_HONEYPOT = 'sg_website';
    const F_TOKEN = 'sg_t';
    const F_INTERACT = 'sg_i';

    private static $cfg = null;
    private static $pdo = null;      // null = not tried yet, false = unavailable
    private static $result = null;

    /** Throw-away mail services (extendable with config 'extra_disposable_domains'). */
    private static $disposable = [
        'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'guerrillamailblock.com', 'grr.la', 'sharklasers.com',
        '10minutemail.com', '10minutemail.net', 'tempmail.com', 'temp-mail.org', 'temp-mail.io', 'tempmailo.com',
        'throwawaymail.com', 'yopmail.com', 'yopmail.net', 'trashmail.com', 'getnada.com', 'nada.email', 'maildrop.cc',
        'dispostable.com', 'fakeinbox.com', 'mailnesia.com', 'mintemail.com', 'moakt.com', 'mohmal.com', 'emailondeck.com',
        'mytemp.email', 'tmail.ws', 'tmpmail.org', 'tmpmail.net', 'burnermail.io', 'inboxkitten.com', 'spamgourmet.com',
        'mailcatch.com', 'mail.tm', '1secmail.com', '1secmail.net', '1secmail.org', 'discard.email', 'discardmail.com',
        'trbvm.com', 'emltmp.com', 'armyspy.com', 'dayrep.com', 'einrot.com', 'gustr.com', 'jourrapide.com', 'rhyta.com',
        'superrito.com', 'teleworm.us', 'cuvox.de', 'spam4.me', 'tempinbox.com', 'sute.jp',
    ];

    /** Words that almost never appear in a genuine local-business enquiry. */
    private static $spamWords = [
        'viagra', 'cialis', 'casino', 'porn', 'xxx', 'escort', 'bitcoin', 'crypto', 'forex', 'binary option',
        'payday loan', 'loan offer', 'seo service', 'seo expert', 'backlink', 'guest post', 'first page of google',
        'rank your website', 'web traffic', 'increase traffic', 'make money', 'earn money online', 'work from home',
        'investment opportunity', 'telegram', 'dating', 'weight loss', 'replica watch', 'click here', 'free gift',
        'lottery', 'you have won',
    ];

    // ------------------------------------------------------------------ config

    public static function defaults(): array
    {
        return [
            'site_id' => 'site',
            'secret' => '',
            'data_dir' => __DIR__ . '/sg-data',
            'timezone' => 'Asia/Kolkata',
            'admin_password_hash' => '',
            'notify_email' => '',
            'selftest_key' => '',
            'disabled' => false,
            'trust_cloudflare' => false,
            // allow = suspicious enquiries still reach your old handler (nothing lost), only flagged in the admin page
            // quarantine = suspicious enquiries are held back (spam page shows them), safest against spam
            'suspicious_action' => 'allow',
            'thresholds' => ['suspicious' => 30, 'spam' => 70],
            'min_seconds' => 3,
            'max_links' => 2,
            'rate' => [
                'ip_per_hour' => 3,
                'email_per_day' => 3,
                'phone_per_day' => 3,
                'subnet_ips_per_hour' => 3,
                'spike_per_10min' => 8,
            ],
            'retention_days' => 365,
            'extra_disposable_domains' => [],
            'extra_spam_words' => [],
            'blocked_scripts' => ['Cyrillic', 'Han', 'Hiragana', 'Katakana', 'Hangul'],
            'turnstile' => ['enabled' => false, 'site_key' => '', 'secret' => ''],
            'success' => [
                'redirect' => '',
                'message' => 'Thank you! We have received your enquiry and will contact you soon.',
                'json' => null,
                'text' => '',
            ],
            'scan_root' => '',
            'hub' => ['url' => '', 'site_key' => '', 'secret' => ''],
        ];
    }

    public static function config(): array
    {
        if (self::$cfg !== null) {
            return self::$cfg;
        }
        $user = [];
        $file = __DIR__ . '/config.php';
        if (is_file($file)) {
            $loaded = include $file;
            if (is_array($loaded)) {
                $user = $loaded;
            }
        }
        return self::$cfg = array_replace_recursive(self::defaults(), $user);
    }

    /** Programmatic config (used by tests and by the desktop app). */
    public static function configure(array $override): void
    {
        self::$cfg = array_replace_recursive(self::defaults(), $override);
        self::$pdo = null;
        self::$result = null;
    }

    // ------------------------------------------------------------------ tokens

    public static function makeToken(?int $ts = null): string
    {
        $cfg = self::config();
        $payload = ($ts ?? time()) . '.' . bin2hex(random_bytes(6));
        return $payload . '.' . self::sign($payload, $cfg);
    }

    private static function sign(string $payload, array $cfg): string
    {
        return substr(hash_hmac('sha256', $payload . '|' . $cfg['site_id'], (string) $cfg['secret']), 0, 24);
    }

    /** @return array [bool valid, int|null ageSeconds, string nonce] */
    private static function verifyToken(string $token, int $now): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3 || !ctype_digit($parts[0]) || !ctype_xdigit($parts[1])) {
            return [false, null, ''];
        }
        $payload = $parts[0] . '.' . $parts[1];
        if (!hash_equals(self::sign($payload, self::config()), $parts[2])) {
            return [false, null, ''];
        }
        return [true, $now - (int) $parts[0], $payload];
    }

    // ------------------------------------------------------------------ small helpers

    private static function len(string $s): int
    {
        return function_exists('mb_strlen') ? mb_strlen($s, 'UTF-8') : strlen($s);
    }

    private static function sub(string $s, int $n): string
    {
        return function_exists('mb_substr') ? mb_substr($s, 0, $n, 'UTF-8') : substr($s, 0, $n);
    }

    private static function lower(string $s): string
    {
        return function_exists('mb_strtolower') ? mb_strtolower($s, 'UTF-8') : strtolower($s);
    }

    public static function clientIp(?array $server = null): string
    {
        $server = $server ?? $_SERVER;
        $ip = (string) ($server['REMOTE_ADDR'] ?? '');
        if (!empty(self::config()['trust_cloudflare']) && !empty($server['HTTP_CF_CONNECTING_IP'])) {
            $cf = (string) $server['HTTP_CF_CONNECTING_IP'];
            if (filter_var($cf, FILTER_VALIDATE_IP)) {
                $ip = $cf;
            }
        }
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    private static function subnet(string $ip): string
    {
        if (strpos($ip, ':') === false) {
            $p = explode('.', $ip);
            return implode('.', array_slice($p, 0, 3)) . '.0/24';
        }
        $bin = @inet_pton($ip);
        return $bin === false ? $ip : bin2hex(substr($bin, 0, 6)) . '::/48';
    }

    private static function norm(string $s): string
    {
        $s = self::lower($s);
        $n = @preg_replace('~https?://\S+~u', '', $s);
        if ($n === null) {
            $n = $s;
        }
        $m = @preg_replace('~[^\p{L}\p{N}]+~u', '', $n);
        return $m === null ? (string) preg_replace('~[^a-z0-9]+~', '', $n) : $m;
    }

    private static function isDisposable(string $domain): bool
    {
        $list = array_merge(self::$disposable, array_map('strtolower', (array) self::config()['extra_disposable_domains']));
        foreach ($list as $d) {
            if ($domain === $d || substr($domain, -strlen($d) - 1) === '.' . $d) {
                return true;
            }
        }
        return false;
    }

    private static function scriptRatio(string $s, array $scripts): float
    {
        $total = (int) @preg_match_all('~\p{L}~u', $s);
        if ($total < 8 || $scripts === []) {
            return 0.0;
        }
        $hit = 0;
        foreach ($scripts as $sc) {
            if (preg_match('~^[A-Za-z_]+$~', (string) $sc)) {
                $hit += (int) @preg_match_all('~\p{' . $sc . '}~u', $s);
            }
        }
        return $hit / $total;
    }

    /** Pull name / email / phone / message out of any form, whatever the field names are. */
    /** @internal used by the hub client */
    public static function extractFields(array $post): array
    {
        return self::extract($post);
    }

    private static function extract(array $post): array
    {
        $out = ['name' => '', 'email' => '', 'phone' => '', 'message' => '', 'all' => []];
        foreach ($post as $k => $v) {
            $k = (string) $k;
            if (preg_match('~^(sg_|cf-turnstile-response$|g-recaptcha-response$|h-captcha-response$)~i', $k)) {
                continue;
            }
            if (preg_match('~pass|pwd|card|cvv|cvc|otp~i', $k)) {
                continue; // never store secrets
            }
            if (is_array($v)) {
                $v = implode(', ', array_map('strval', array_filter($v, 'is_scalar')));
            }
            if (!is_scalar($v)) {
                continue;
            }
            $out['all'][$k] = self::sub(trim((string) $v), 5000);
        }
        $rest = [];
        foreach ($out['all'] as $k => $v) {
            $lk = strtolower($k);
            if ($v === '') {
                continue;
            }
            if ($out['email'] === '' && strpos($lk, 'mail') !== false) {
                $out['email'] = $v;
            } elseif ($out['phone'] === '' && preg_match('~phone|mobile|\btel|whatsapp|cell|contact_?(no|num)~', $lk)) {
                $out['phone'] = $v;
            } elseif ($out['name'] === '' && preg_match('~(^|[_\-\s])name$|^name|fullname|your-?name~', $lk)) {
                $out['name'] = $v;
            } elseif ($out['message'] === '' && preg_match('~message|msg|comment|enquiry|inquiry|query|detail|requirement|remark|description|note|text~', $lk)) {
                $out['message'] = $v;
            } else {
                $rest[$k] = $v;
            }
        }
        foreach ($rest as $v) {
            if ($out['email'] === '' && filter_var($v, FILTER_VALIDATE_EMAIL)) {
                $out['email'] = $v;
            } elseif ($out['phone'] === '' && preg_match('~^\+?[\d][\d\s\-()]{7,}$~', $v)) {
                $out['phone'] = $v;
            }
        }
        if ($out['message'] === '') {
            $best = '';
            foreach ($rest as $v) {
                if (self::len($v) > self::len($best) && $v !== $out['email'] && $v !== $out['phone']) {
                    $best = $v;
                }
            }
            if (self::len($best) > 20) {
                $out['message'] = $best;
            }
        }
        return $out;
    }

    // ------------------------------------------------------------------ storage

    public static function dataPath(): ?string
    {
        $dir = (string) self::config()['data_dir'];
        if ($dir === '') {
            return null;
        }
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return null;
        }
        if (!is_writable($dir)) {
            return null;
        }
        $ht = $dir . '/.htaccess';
        if (!is_file($ht)) {
            @file_put_contents($ht, "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n");
        }
        if (!is_file($dir . '/index.html')) {
            @file_put_contents($dir . '/index.html', '');
        }
        return $dir;
    }

    /** SQLite handle, or null when storage is not available (guard then runs stateless). */
    public static function pdo(): ?PDO
    {
        if (self::$pdo !== null) {
            return self::$pdo ?: null;
        }
        self::$pdo = false;
        try {
            if (!extension_loaded('pdo_sqlite')) {
                return null;
            }
            $dir = self::dataPath();
            if ($dir === null) {
                return null;
            }
            $file = $dir . '/guard-' . substr(hash('sha256', (string) self::config()['secret'] . 'db'), 0, 10) . '.sqlite';
            $pdo = new PDO('sqlite:' . $file, null, null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
            $pdo->exec('PRAGMA busy_timeout = 3000');
            try {
                $pdo->exec('PRAGMA journal_mode = WAL');
            } catch (\Throwable $e) {
                // some filesystems refuse WAL, default mode is fine
            }
            self::migrate($pdo);
            self::$pdo = $pdo;
            return $pdo;
        } catch (\Throwable $e) {
            self::$pdo = false;
            return null;
        }
    }

    private static function migrate(PDO $pdo): void
    {
        $pdo->exec('CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, ip TEXT, subnet TEXT, ua TEXT,
            name TEXT, email TEXT, phone TEXT, msg_hash TEXT, score INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL, override TEXT, reasons TEXT, fields TEXT, page TEXT, referer TEXT,
            utm_source TEXT, utm_medium TEXT, utm_campaign TEXT, gclid TEXT)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS i_ts ON submissions(ts)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS i_ip ON submissions(ip, ts)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS i_subnet ON submissions(subnet, ts)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS i_email ON submissions(email, ts)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS i_phone ON submissions(phone, ts)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS i_hash ON submissions(msg_hash, ts)');
        $pdo->exec('CREATE TABLE IF NOT EXISTS tokens (nonce TEXT PRIMARY KEY, first_ts INTEGER NOT NULL, uses INTEGER NOT NULL DEFAULT 0)');
        $pdo->exec('CREATE TABLE IF NOT EXISTS logins (ip TEXT, ts INTEGER)');
        $has = false;
        foreach ($pdo->query('PRAGMA table_info(submissions)')->fetchAll() as $c) {
            if ($c['name'] === 'hub_sent') {
                $has = true;
            }
        }
        if (!$has) {
            $pdo->exec('ALTER TABLE submissions ADD COLUMN hub_sent INTEGER NOT NULL DEFAULT 0');
            $pdo->exec('UPDATE submissions SET hub_sent = 1'); // old rows predate the hub: do not flood it
        }
        $pdo->exec('CREATE INDEX IF NOT EXISTS i_hub ON submissions(hub_sent, id)');
    }

    // ------------------------------------------------------------------ Cloudflare Turnstile (optional)

    /** @return bool|null true/false = verdict, null = could not verify (network) */
    private static function verifyTurnstile(string $response, string $ip): ?bool
    {
        $t = self::config()['turnstile'];
        $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        $body = http_build_query(['secret' => $t['secret'], 'response' => $response, 'remoteip' => $ip]);
        $raw = false;
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 4, CURLOPT_CONNECTTIMEOUT => 3,
            ]);
            $raw = curl_exec($ch);
        } elseif (ini_get('allow_url_fopen')) {
            $ctx = stream_context_create(['http' => [
                'method' => 'POST', 'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                'content' => $body, 'timeout' => 4,
            ]]);
            $raw = @file_get_contents($url, false, $ctx);
        }
        if (!is_string($raw)) {
            return null;
        }
        $j = json_decode($raw, true);
        return is_array($j) ? !empty($j['success']) : null;
    }

    // ------------------------------------------------------------------ the check

    /**
     * Score one submission, log it, return the verdict.
     * @return array{id:int,status:string,score:int,reasons:array,ip:string,logged:bool}
     */
    public static function check(array $post, ?array $server = null, ?int $now = null): array
    {
        $cfg = self::config();
        $server = $server ?? $_SERVER;
        $now = $now ?? time();
        $score = 0;
        $reasons = [];
        $add = function (int $pts, string $why) use (&$score, &$reasons) {
            $score += $pts;
            $reasons[] = $why . ' (+' . $pts . ')';
        };

        $ip = self::clientIp($server);
        $subnet = self::subnet($ip);
        $ua = self::sub((string) ($server['HTTP_USER_AGENT'] ?? ''), 300);
        $f = self::extract($post);
        $blob = implode("\n", array_values($f['all']));

        // 1. honeypot: humans never see this field
        if (trim((string) ($post[self::F_HONEYPOT] ?? '')) !== '') {
            $add(100, 'Hidden honeypot field was filled');
        }

        // 2. signed time token
        $nonce = '';
        $tok = (string) ($post[self::F_TOKEN] ?? '');
        if ($tok === '') {
            $add(50, 'No form token (JavaScript blocked or a bot posting directly)');
        } else {
            list($ok, $age, $nonce) = self::verifyToken($tok, $now);
            if (!$ok) {
                $add(60, 'Forged or invalid form token');
                $nonce = '';
            } else {
                if ($age < (int) $cfg['min_seconds']) {
                    $add(40, 'Submitted ' . max(0, (int) $age) . 's after page load (too fast)');
                } elseif ($age > 86400) {
                    $add(10, 'Form token older than 24 hours');
                }
                if ((int) ($post[self::F_INTERACT] ?? 0) <= 0) {
                    $add(10, 'No keyboard / mouse / touch activity on the form');
                }
            }
        }

        // 3. Cloudflare Turnstile (only when switched on)
        $ts = $cfg['turnstile'];
        if (!empty($ts['enabled']) && $ts['secret'] !== '') {
            $resp = (string) ($post['cf-turnstile-response'] ?? '');
            if ($resp === '') {
                $add(60, 'Turnstile challenge missing');
            } else {
                $verdict = self::verifyTurnstile($resp, $ip);
                if ($verdict === false) {
                    $add(60, 'Turnstile challenge failed');
                } elseif ($verdict === null) {
                    $reasons[] = 'Turnstile could not be verified (network), ignored';
                }
            }
        }

        // 4. browser fingerprint basics
        if ($ua === '') {
            $add(30, 'No User-Agent header');
        } elseif (preg_match('~curl|wget|python|httpclient|java/|libwww|scrapy|go-http|okhttp|headless|phantom|bot\b|spider|crawl~i', $ua)) {
            $add(40, 'Automation tool User-Agent');
        }

        // 5. email quality
        if ($f['email'] !== '') {
            if (!filter_var($f['email'], FILTER_VALIDATE_EMAIL)) {
                $add(20, 'Invalid email format');
            } else {
                $dom = strtolower((string) substr((string) strrchr($f['email'], '@'), 1));
                if (self::isDisposable($dom)) {
                    $add(30, 'Disposable email domain (' . $dom . ')');
                }
            }
        }

        // 6. content: links, spam words, foreign script, shouting
        $links = (int) preg_match_all('~(https?://|ftp://|www\.)~i', $blob) + (int) preg_match_all('~\[url[=\]]|<a\s~i', $blob);
        $maxLinks = (int) $cfg['max_links'];
        if ($links > $maxLinks) {
            $add(min(45, 20 + 10 * max(0, $links - $maxLinks - 1)), $links . ' links in the message');
        }
        $lowBlob = self::lower($blob);
        $hits = 0;
        foreach (array_merge(self::$spamWords, array_map('strtolower', (array) $cfg['extra_spam_words'])) as $w) {
            if ($w !== '' && strpos($lowBlob, $w) !== false) {
                $hits++;
            }
        }
        if ($hits > 0) {
            $add(min(45, 25 + 10 * ($hits - 1)), $hits . ' spam keyword(s)');
        }
        $ratio = self::scriptRatio($blob, (array) $cfg['blocked_scripts']);
        if ($ratio >= 0.3) {
            $add(20, 'Text mostly in a foreign script (Cyrillic/CJK)');
        }
        $letters = (int) preg_match_all('~[A-Za-z]~', $blob);
        if ($letters >= 25 && (int) preg_match_all('~[A-Z]~', $blob) / $letters > 0.85) {
            $add(10, 'Message is ALL CAPS');
        }

        // 7. history: duplicates, rate limits, bursts (needs SQLite, skipped if missing)
        $pdo = self::pdo();
        $hash = '';
        $content = $f['message'] !== '' ? $f['message'] : '';
        $normalized = self::norm($content);
        if (self::len($normalized) >= 12) {
            $hash = sha1($normalized);
        }
        $phoneKey = $f['phone'] !== '' ? substr((string) preg_replace('~\D+~', '', $f['phone']), -10) : '';
        $emailKey = strtolower($f['email']);
        if ($pdo) {
            try {
                $one = function (string $sql, array $args) use ($pdo): int {
                    $st = $pdo->prepare($sql);
                    $st->execute($args);
                    return (int) $st->fetchColumn();
                };
                $rate = $cfg['rate'];
                if ($nonce !== '') {
                    $pdo->prepare('INSERT OR IGNORE INTO tokens(nonce, first_ts, uses) VALUES(?, ?, 0)')->execute([$nonce, $now]);
                    $pdo->prepare('UPDATE tokens SET uses = uses + 1 WHERE nonce = ?')->execute([$nonce]);
                    $uses = $one('SELECT uses FROM tokens WHERE nonce = ?', [$nonce]);
                    if ($uses >= 3) {
                        $add(40, 'Same form token reused ' . $uses . ' times (replay)');
                    } elseif ($uses === 2) {
                        $add(15, 'Form token submitted twice');
                    }
                }
                if ($hash !== '') {
                    $dup = $one('SELECT COUNT(*) FROM submissions WHERE msg_hash = ? AND ts > ?', [$hash, $now - 7 * 86400]);
                    if ($dup >= 2) {
                        $add(60, 'Identical message already received ' . $dup . ' times');
                    } elseif ($dup === 1) {
                        $add(35, 'Identical message already received once');
                    }
                }
                if ($ip !== '0.0.0.0') {
                    if ($one('SELECT COUNT(*) FROM submissions WHERE ip = ? AND ts > ?', [$ip, $now - 3600]) >= (int) $rate['ip_per_hour']) {
                        $add(30, 'Too many enquiries from this IP in one hour');
                    }
                    $others = $one('SELECT COUNT(DISTINCT ip) FROM submissions WHERE subnet = ? AND ip != ? AND ts > ?', [$subnet, $ip, $now - 3600]);
                    if ($others >= (int) $rate['subnet_ips_per_hour']) {
                        $add(15, 'Many different IPs from the same network range');
                    }
                }
                if ($emailKey !== '' && $one('SELECT COUNT(*) FROM submissions WHERE email = ? AND ts > ?', [$emailKey, $now - 86400]) >= (int) $rate['email_per_day']) {
                    $add(25, 'Same email used repeatedly today');
                }
                if (strlen($phoneKey) >= 7 && $one('SELECT COUNT(*) FROM submissions WHERE phone = ? AND ts > ?', [$phoneKey, $now - 86400]) >= (int) $rate['phone_per_day']) {
                    $add(25, 'Same phone number used repeatedly today');
                }
                if ($one('SELECT COUNT(*) FROM submissions WHERE ts > ?', [$now - 600]) >= (int) $rate['spike_per_10min']) {
                    $add(15, 'Burst of enquiries on this site in the last 10 minutes');
                }
            } catch (\Throwable $e) {
                $reasons[] = '(history checks skipped: storage error)';
            }
        }

        $t = $cfg['thresholds'];
        $status = $score >= (int) $t['spam'] ? 'spam' : ($score >= (int) $t['suspicious'] ? 'suspicious' : 'real');

        // 8. log everything (real leads included: this is the admin's lead list)
        $id = 0;
        $logged = false;
        if ($pdo) {
            try {
                $st = $pdo->prepare('INSERT INTO submissions
                    (ts, ip, subnet, ua, name, email, phone, msg_hash, score, status, reasons, fields, page, referer, utm_source, utm_medium, utm_campaign, gclid)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
                $st->execute([
                    $now, $ip, $subnet, $ua, self::sub($f['name'], 200), $emailKey, $phoneKey, $hash, min(100, $score), $status,
                    json_encode($reasons, JSON_UNESCAPED_UNICODE), json_encode($f['all'], JSON_UNESCAPED_UNICODE),
                    self::sub((string) ($post['sg_page'] ?? ''), 300), self::sub((string) ($server['HTTP_REFERER'] ?? ''), 300),
                    self::sub((string) ($post['sg_utm_source'] ?? ''), 200), self::sub((string) ($post['sg_utm_medium'] ?? ''), 200),
                    self::sub((string) ($post['sg_utm_campaign'] ?? ''), 200), self::sub((string) ($post['sg_gclid'] ?? ''), 200),
                ]);
                $id = (int) $pdo->lastInsertId();
                $logged = true;
                if (random_int(1, 60) === 1) {
                    $pdo->prepare('DELETE FROM submissions WHERE ts < ?')->execute([$now - (int) $cfg['retention_days'] * 86400]);
                    $pdo->prepare('DELETE FROM tokens WHERE first_ts < ?')->execute([$now - 2 * 86400]);
                }
            } catch (\Throwable $e) {
                $reasons[] = '(could not log submission)';
            }
        }

        return ['id' => $id, 'status' => $status, 'score' => min(100, $score), 'reasons' => $reasons, 'ip' => $ip, 'logged' => $logged];
    }

    // ------------------------------------------------------------------ the one-liner for form handlers

    /**
     * Put this at the top of a form handler. Spam gets a fake "thank you" (bots never learn they were
     * blocked) and your old code is never reached. Never throws, never breaks the site.
     */
    public static function guard(array $override = []): ?array
    {
        try {
            if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
                return null;
            }
            $cfg = self::config();
            if (!empty($cfg['disabled']) || $cfg['secret'] === '') {
                return null;
            }
            $res = self::check($_POST);
            self::$result = $res;
            if (class_exists('SgHub', false)) {
                SgHub::schedule(true); // tell the central hub after the visitor got their answer
            }
            $GLOBALS['SG_RESULT'] = $res;
            foreach (array_keys($_POST) as $k) {
                if (preg_match('~^(sg_|cf-turnstile-response$)~', (string) $k)) {
                    unset($_POST[$k], $_REQUEST[$k]);
                }
            }
            if ($res['status'] === 'spam' || ($res['status'] === 'suspicious' && $cfg['suspicious_action'] === 'quarantine')) {
                $success = $cfg['success'];
                if (isset($override['success']) && is_array($override['success'])) {
                    $success = array_merge($success, $override['success']);
                }
                self::fakeSuccess($success);
            }
            return $res;
        } catch (\Throwable $e) {
            return null;
        }
    }

    public static function result(): ?array
    {
        return self::$result;
    }

    private static function fakeSuccess(array $s): void
    {
        $accept = strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));
        $ajax = strtolower((string) ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) === 'xmlhttprequest'
            || (strpos($accept, 'json') !== false && strpos($accept, 'text/html') === false);
        if (!headers_sent()) {
            header('Cache-Control: no-store');
        }
        if ($ajax && isset($s['text']) && is_string($s['text']) && $s['text'] !== '') {
            header('Content-Type: text/plain; charset=utf-8');
            echo $s['text'];
            exit;
        }
        if ($ajax) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(is_array($s['json']) ? $s['json'] : ['success' => true, 'status' => 'success', 'message' => $s['message']]);
            exit;
        }
        if ($s['redirect'] !== '') {
            header('Location: ' . str_replace(["\r", "\n"], '', (string) $s['redirect']), true, 303);
            exit;
        }
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Thank you</title>'
            . '<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;text-align:center">'
            . '<h1>Thank you!</h1><p>' . htmlspecialchars((string) $s['message'], ENT_QUOTES, 'UTF-8') . '</p>'
            . '<p><a href="javascript:history.back()">&larr; Back</a></p></body>';
        exit;
    }
}
