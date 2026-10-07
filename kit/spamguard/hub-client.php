<?php
/**
 * SpamGuard -> central hub reporter.
 *
 * Sends (1) real + suspicious enquiries and (2) a heartbeat (status + daily counts) to the hub.
 * Design rules:
 *  - Never breaks a form: every call is wrapped, short timeouts, silent on failure.
 *  - No cron needed: it piggybacks on traffic (a form submit, or a page load asking token.php).
 *  - Spam text is never sent, only daily COUNTS (idempotent: the hub replaces, it does not add).
 *  - Retries are automatic: unsent rows stay marked hub_sent=0; failures back off 5 min -> 1 h.
 */
final class SgHub
{
    private static bool $scheduled = false;

    public static function settings(): ?array
    {
        $h = SpamGuard::config()['hub'] ?? null;
        if (!is_array($h) || empty($h['url']) || empty($h['site_key']) || empty($h['secret'])) {
            return null;
        }
        $url = rtrim((string) $h['url'], '/');
        $host = (string) parse_url($url, PHP_URL_HOST);
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        $local = in_array($host, ['127.0.0.1', 'localhost', '::1'], true);
        if ($scheme !== 'https' && !($scheme === 'http' && $local)) {
            return null; // secrets and enquiries only travel over HTTPS
        }
        return ['url' => $url, 'key' => (string) $h['site_key'], 'secret' => (string) $h['secret']];
    }

    /** Run after the response has been sent to the visitor. */
    public static function schedule(bool $events = true): void
    {
        if (self::$scheduled || self::settings() === null) {
            return;
        }
        self::$scheduled = true;
        register_shutdown_function(static function () use ($events) {
            try {
                if (function_exists('fastcgi_finish_request')) {
                    @fastcgi_finish_request();
                }
                SgHub::tick(false, $events);
            } catch (\Throwable $e) {
            }
        });
    }

    private static function marker(string $name): ?string
    {
        $d = SpamGuard::dataPath();
        return $d === null ? null : $d . '/' . $name;
    }

    /**
     * Do whatever is due. $events: also flush unsent enquiries (a form was just submitted).
     * Cheap when nothing is due: a single filemtime().
     */
    public static function tick(bool $force = false, bool $events = false): void
    {
        try {
            $s = self::settings();
            if ($s === null) {
                return;
            }
            $back = self::marker('hub.backoff');
            if (!$force && $back && is_file($back) && time() < (int) @filemtime($back)) {
                return; // hub was unreachable recently
            }
            $hb = self::marker('hub.beat');
            $beatDue = $force || !$hb || !is_file($hb) || (time() - (int) @filemtime($hb)) > 6 * 3600;
            if (!$beatDue && !$events) {
                return;
            }
            $lock = self::marker('hub.lock');
            $fh = $lock ? @fopen($lock, 'c') : false;
            if ($fh && !@flock($fh, LOCK_EX | LOCK_NB)) {
                return; // another request is already talking to the hub
            }
            $ok = true;
            if ($events || $beatDue) {
                $ok = self::flushEvents($s) && $ok;
            }
            if ($beatDue) {
                $ok = self::heartbeat($s) && $ok;
                if ($ok && $hb) {
                    @touch($hb);
                }
            }
            if ($back) {
                if ($ok) {
                    @unlink($back);
                    @unlink($back . '.n');
                } else {
                    $n = min(5, 1 + (int) @file_get_contents($back . '.n'));
                    @file_put_contents($back . '.n', (string) $n);
                    @touch($back, time() + min(3600, 300 * (2 ** ($n - 1))));
                }
            }
            if ($fh) {
                @flock($fh, LOCK_UN);
                @fclose($fh);
            }
        } catch (\Throwable $e) {
        }
    }

    private static function eventId(array $r, string $siteKey): string
    {
        return substr(hash('sha256', $siteKey . '|' . $r['ts'] . '|' . $r['id'] . '|' . $r['msg_hash']), 0, 32);
    }

    private static function flushEvents(array $s): bool
    {
        $pdo = SpamGuard::pdo();
        if (!$pdo) {
            return true;
        }
        $rows = $pdo->query("SELECT * FROM submissions WHERE hub_sent = 0 AND COALESCE(override, status) IN ('real','suspicious') ORDER BY id LIMIT 20")->fetchAll();
        if (!$rows) {
            $pdo->exec("UPDATE submissions SET hub_sent = 1 WHERE hub_sent = 0 AND COALESCE(override, status) NOT IN ('real','suspicious')");
            return true;
        }
        $events = [];
        foreach ($rows as $r) {
            $fields = json_decode((string) $r['fields'], true);
            $fields = is_array($fields) ? array_slice($fields, 0, 25, true) : [];
            foreach ($fields as $k => $v) {
                $fields[$k] = mb_substr((string) $v, 0, 1500);
            }
            $f = SpamGuard::extractFields($fields);
            $events[] = [
                'id' => self::eventId($r, $s['key']),
                'status' => (string) ($r['override'] ?: $r['status']),
                'score' => (int) $r['score'],
                'reasons' => array_slice((array) json_decode((string) $r['reasons'], true), 0, 12),
                'at' => (int) $r['ts'],
                'name' => $f['name'], 'email' => $f['email'], 'phone' => $f['phone'], 'message' => $f['message'],
                'fields' => $fields,
                'page' => (string) $r['page'], 'referer' => (string) $r['referer'],
                'utm' => ['source' => (string) $r['utm_source'], 'medium' => (string) $r['utm_medium'], 'campaign' => (string) $r['utm_campaign'], 'gclid' => (string) $r['gclid']],
                'ip_hash' => substr(hash('sha256', (string) SpamGuard::config()['secret'] . '|ip|' . $r['ip']), 0, 16),
            ];
        }
        $res = self::post($s, ['v' => 1, 'type' => 'events', 'events' => $events]);
        if ($res === null) {
            return false;
        }
        $ids = array_map('intval', array_column($rows, 'id'));
        $pdo->exec('UPDATE submissions SET hub_sent = 1 WHERE id IN (' . implode(',', $ids) . ')');
        return true;
    }

    private static function heartbeat(array $s): bool
    {
        $cfg = SpamGuard::config();
        $daily = [];
        $pdo = SpamGuard::pdo();
        if ($pdo) {
            $st = $pdo->prepare("SELECT date(ts,'unixepoch') d, COALESCE(override,status) s, COUNT(*) c FROM submissions WHERE ts > ? GROUP BY d, s");
            $st->execute([time() - 4 * 86400]);
            foreach ($st->fetchAll() as $r) {
                $daily[$r['d']][$r['s']] = (int) $r['c'];
            }
        }
        $data = [
            'v' => 1, 'type' => 'heartbeat',
            'kit' => SpamGuard::VERSION, 'php' => PHP_VERSION,
            'host' => (string) ($_SERVER['HTTP_HOST'] ?? ''),
            'turnstile' => !empty($cfg['turnstile']['enabled']),
            'suspicious_action' => (string) $cfg['suspicious_action'],
            'storage' => $pdo ? 'ok' : 'missing',
            'daily' => $daily,
        ];
        return self::post($s, $data) !== null;
    }

    /** @return array|null decoded JSON answer, or null when the hub could not be reached / refused */
    public static function post(array $s, array $payload, int $timeout = 4): ?array
    {
        $body = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($body === false) {
            return null;
        }
        $ts = (string) time();
        $headers = [
            'Content-Type: application/json',
            'X-SG-Key: ' . $s['key'],
            'X-SG-Ts: ' . $ts,
            'X-SG-Sig: ' . hash_hmac('sha256', $ts . "\n" . $body, $s['secret']),
            'User-Agent: SpamGuard/' . SpamGuard::VERSION,
        ];
        $url = $s['url'] . '/api/ingest.php';
        $out = false;
        $code = 0;
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => $headers, CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_FOLLOWLOCATION => false, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2]);
            $out = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
        } else {
            $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => implode("\r\n", $headers), 'content' => $body, 'timeout' => $timeout, 'ignore_errors' => true, 'follow_location' => 0]]);
            $out = @file_get_contents($url, false, $ctx);
            if (isset($http_response_header[0]) && preg_match('~\s(\d{3})\s~', $http_response_header[0], $m)) {
                $code = (int) $m[1];
            }
        }
        if ($out === false || $code < 200 || $code >= 300) {
            return null;
        }
        $j = json_decode((string) $out, true);
        return is_array($j) && !empty($j['ok']) ? $j : null;
    }
}
