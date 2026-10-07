<?php
/**
 * SpamGuard apply layer (PHP pages only).
 *
 * Put ONE line at the very top of a PHP page (Studio does this for you):
 *     require_once __DIR__ . '/spamguard/sg-apply.php';   // path as needed
 * It then rewrites the page's HTML on its way out, using what the central hub sent:
 *   1. SEO edits for this URL: title, description, social share tags, canonical, robots, JSON-LD
 *   2. old phone / email / address  ->  the new central contact details (in text, tel:, mailto:, WhatsApp links)
 * FAIL-OPEN: if anything goes wrong the original page is sent unchanged. No hub data = no buffering at all.
 *
 * Also gives PHP pages:   <?= sg_contact('phone') ?>
 */
if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME']) && @realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    http_response_code(403);
    exit;
}
require_once __DIR__ . '/spamguard.php';

/** Current central value of a contact field ('phone', 'email', 'address', ... or one of your custom fields). */
function sg_contact(string $key, string $default = ''): string
{
    try {
        $c = class_exists('SgHub', false) ? SgHub::readSynced('contact.json') : null;
        $v = $c['f'][$key] ?? ($c['custom'][$key] ?? null);
        return is_string($v) && $v !== '' ? $v : $default;
    } catch (\Throwable $e) {
        return $default;
    }
}

final class SgApply
{
    /** Called by the one-line include. */
    public static function start(): void
    {
        static $on = false;
        if ($on || PHP_SAPI === 'cli') {
            return;
        }
        $on = true;
        try {
            if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true) || strtolower((string) ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) === 'xmlhttprequest' || !class_exists('SgHub', false)) {
                return;
            }
            if (self::plan() === null) {
                return; // nothing to apply: do not touch the output at all
            }
            ob_start([self::class, 'callback']);
        } catch (\Throwable $e) {
        }
    }

    /** @return array{seo:?array,contact:?array}|null */
    private static function plan(): ?array
    {
        $seo = null;
        $s = SgHub::readSynced('seo.json');
        if ($s && !empty($s['pages']) && is_array($s['pages'])) {
            $seo = self::matchPage($s['pages'], (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH));
        }
        $c = SgHub::readSynced('contact.json');
        $contact = $c && !empty($c['legacy']) && is_array($c['legacy']) && !empty($c['f']) ? $c : null;
        return $seo === null && $contact === null ? null : ['seo' => $seo, 'contact' => $contact];
    }

    /** Hub stores the real file path; visitors may use the pretty URL (/ for /index.php, /about for /about.php). */
    public static function matchPage(array $pages, string $path): ?array
    {
        $path = rawurldecode($path === '' ? '/' : $path);
        $cands = [$path, rtrim($path, '/') ?: '/', rtrim($path, '/') . '/index.php', rtrim($path, '/') . '/index.html', rtrim($path, '/') . '.php', rtrim($path, '/') . '.html'];
        if (preg_match('~^(.*/)index\.(php|html?)$~i', $path, $m)) {
            $cands[] = $m[1];
        }
        foreach ($pages as $p) {
            if (isset($p['p']) && in_array($p['p'], $cands, true)) {
                return $p;
            }
        }
        return null;
    }

    public static function callback(string $buf, int $phase)
    {
        try {
            // only act when the whole document arrives in one piece
            if (!($phase & PHP_OUTPUT_HANDLER_START) || !($phase & PHP_OUTPUT_HANDLER_FINAL) || $buf === '' || strlen($buf) > 3000000) {
                return false;
            }
            if (http_response_code() !== 200 && http_response_code() !== false) {
                return false;
            }
            foreach (headers_list() as $h) {
                if (stripos($h, 'content-type:') === 0 && stripos($h, 'html') === false) {
                    return false;
                }
            }
            if (stripos($buf, '<html') === false && stripos($buf, '<head') === false) {
                return false;
            }
            $plan = self::plan();
            if ($plan === null) {
                return false;
            }
            $out = $buf;
            if ($plan['seo']) {
                $out = self::seo($out, $plan['seo']);
            }
            if ($plan['contact']) { // after SEO, so a phone inside an edited schema is swapped as well
                $out = self::contact($out, $plan['contact']);
            }
            return $out === $buf ? false : $out;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /* ---------------------------------------------------------------- SEO */

    private static function esc(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

    /** Replace the first <meta {attr}="{val}"> with $tag; when absent insert it before </head> (if $add). */
    private static function setTag(string $html, string $pattern, string $tag, bool $add): string
    {
        $n = 0;
        $out = preg_replace_callback($pattern, static fn() => $tag, $html, 1, $n);
        if ($out === null) {
            return $html;
        }
        if ($n === 0 && $add) {
            $pos = stripos($out, '</head>');
            if ($pos !== false) {
                $out = substr($out, 0, $pos) . $tag . "\n" . substr($out, $pos);
            }
        }
        return $out;
    }
    private static function metaRe(string $attr, string $val): string
    {
        return '~<meta\b(?=[^>]*\b' . $attr . '\s*=\s*["\']' . preg_quote($val, '~') . '["\'])[^>]*>~i';
    }

    /** @param array $o keys t(itle) d(escription) i(mage) c(anonical) r(obots) s(chema json) */
    public static function seo(string $html, array $o): string
    {
        if (!empty($o['t'])) {
            $t = self::esc((string) $o['t']);
            $n = 0;
            $h2 = preg_replace_callback('~<title\b[^>]*>.*?</title>~is', static fn() => '<title>' . $t . '</title>', $html, 1, $n);
            $html = $h2 ?? $html;
            if ($n === 0) {
                $html = self::setTag($html, '~(?!)~', '<title>' . $t . '</title>', true);
            }
            $html = self::setTag($html, self::metaRe('property', 'og:title'), '<meta property="og:title" content="' . $t . '">', true);
            $html = self::setTag($html, self::metaRe('name', 'twitter:title'), '<meta name="twitter:title" content="' . $t . '">', false);
        }
        if (!empty($o['d'])) {
            $d = self::esc((string) $o['d']);
            $html = self::setTag($html, self::metaRe('name', 'description'), '<meta name="description" content="' . $d . '">', true);
            $html = self::setTag($html, self::metaRe('property', 'og:description'), '<meta property="og:description" content="' . $d . '">', true);
            $html = self::setTag($html, self::metaRe('name', 'twitter:description'), '<meta name="twitter:description" content="' . $d . '">', false);
        }
        if (!empty($o['i'])) {
            $i = self::esc((string) $o['i']);
            $html = self::setTag($html, self::metaRe('property', 'og:image'), '<meta property="og:image" content="' . $i . '">', true);
            $html = self::setTag($html, self::metaRe('name', 'twitter:image'), '<meta name="twitter:image" content="' . $i . '">', false);
        }
        if (!empty($o['c'])) {
            $html = self::setTag($html, '~<link\b(?=[^>]*\brel\s*=\s*["\']canonical["\'])[^>]*>~i', '<link rel="canonical" href="' . self::esc((string) $o['c']) . '">', true);
        }
        if (!empty($o['r']) && preg_match('~^(no)?index,(no)?follow$~', (string) $o['r'])) {
            $html = self::setTag($html, self::metaRe('name', 'robots'), '<meta name="robots" content="' . self::esc((string) $o['r']) . '">', true);
        }
        if (!empty($o['s'])) {
            $j = json_decode((string) $o['s'], true);
            if (is_array($j)) {
                $tag = '<script type="application/ld+json">' . str_replace('</', '<\/', (string) json_encode($j, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</script>';
                $pos = stripos($html, '</head>');
                if ($pos !== false) {
                    $html = substr($html, 0, $pos) . $tag . "\n" . substr($html, $pos);
                }
            }
        }
        return $html;
    }

    /* ------------------------------------------------------------ contact */

    private static function digits(string $s): string { return (string) preg_replace('~\D~', '', $s); }
    private static function samePhone(string $a, string $b): bool
    {
        $a = self::digits($a);
        $b = self::digits($b);
        if (strlen($a) < 6 || strlen($b) < 6) {
            return false;
        }
        return strlen($a) >= 10 && strlen($b) >= 10 ? substr($a, -10) === substr($b, -10) : $a === $b;
    }
    private static function phoneRe(string $old): ?string
    {
        $d = self::digits($old);
        if (strlen($d) < 6) {
            return null;
        }
        $core = implode('[\s().\-]{0,3}', str_split($d));
        $prefix = strlen($d) === 10 ? '(?:\+?\d{1,3}[\s.\-]{0,3})?' : '';
        return '~(^|[^\d+])(' . $prefix . '\(?' . $core . ')(?!\d)~u';
    }

    /** @return array<int,array{kind:string,old:string,new:string}> */
    private static function pairs(array $c): array
    {
        $out = [];
        foreach (is_array($c['legacy'] ?? null) ? $c['legacy'] : [] as $field => $olds) {
            $new = (string) ($c['f'][$field] ?? '');
            if ($new === '' || !is_array($olds)) {
                continue;
            }
            $kind = in_array($field, ['phone', 'phone2', 'whatsapp'], true) ? 'phone' : ($field === 'email' ? 'email' : 'text');
            foreach ($olds as $old) {
                $old = trim((string) $old);
                if ($old !== '' && $old !== $new && ($kind !== 'phone' || self::digits($old) !== self::digits($new))) {
                    $out[] = ['kind' => $kind, 'old' => $old, 'new' => $new];
                }
            }
        }
        return $out;
    }

    private static function replaceText(string $text, array $pairs, bool $textOnly): string
    {
        foreach ($pairs as $p) {
            if ($p['kind'] === 'phone' && ($re = self::phoneRe($p['old']))) {
                $text = (string) preg_replace_callback($re, static fn($m) => $m[1] . $p['new'], $text);
            } elseif ($p['kind'] === 'email') {
                $text = str_ireplace($p['old'], $p['new'], $text);
            } elseif ($p['kind'] === 'text' && !$textOnly) {
                $words = preg_split('~\s+~u', $p['old'], -1, PREG_SPLIT_NO_EMPTY) ?: [];
                if ($words) {
                    $text = (string) preg_replace_callback('~' . implode('\s+', array_map(fn($w) => preg_quote($w, '~'), $words)) . '~iu', static fn() => $p['new'], $text);
                }
            }
        }
        return $text;
    }

    private static function replaceAttrs(string $tag, array $pairs): string
    {
        if (stripos($tag, 'href') === false) {
            return $tag;
        }
        return (string) preg_replace_callback('~(\bhref\s*=\s*)(["\']?)([^"\'>\s]+)~i', static function ($m) use ($pairs) {
            $url = $m[3];
            $dec = html_entity_decode($url, ENT_QUOTES | ENT_HTML5);
            foreach ($pairs as $p) {
                if ($p['kind'] === 'phone') {
                    if (preg_match('~^(tel:)(.*)$~i', $dec, $x) && self::samePhone(rawurldecode($x[2]), $p['old'])) {
                        $nd = self::digits($p['new']);
                        return $m[1] . $m[2] . $x[1] . (strpos($p['new'], '+') !== false ? '+' : '') . $nd;
                    }
                    if (preg_match('~^(https?://(?:wa\.me/|api\.whatsapp\.com/send\?phone=|wa\.me/send\?phone=))([\d+\s%\-]+)(.*)$~i', $dec, $x) && self::samePhone(rawurldecode($x[2]), $p['old'])) {
                        return $m[1] . $m[2] . $x[1] . self::digits($p['new']) . $x[3];
                    }
                } elseif ($p['kind'] === 'email' && preg_match('~^(mailto:)([^?]*)(.*)$~i', $dec, $x) && strcasecmp(rawurldecode($x[2]), $p['old']) === 0) {
                    return $m[1] . $m[2] . $x[1] . $p['new'] . $x[3];
                }
            }
            return $m[0];
        }, $tag);
    }

    public static function contact(string $html, array $c): string
    {
        $pairs = self::pairs($c);
        if (!$pairs) {
            return $html;
        }
        $parts = preg_split('~(<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->|<[^>]+>)~is', $html, -1, PREG_SPLIT_DELIM_CAPTURE);
        if ($parts === false) {
            return $html;
        }
        foreach ($parts as $i => $seg) {
            if ($seg === '') {
                continue;
            }
            if ($seg[0] !== '<') {
                $parts[$i] = self::replaceText($seg, $pairs, false);
            } elseif (preg_match('~^<script\b[^>]*application/ld\+json~i', $seg)) {
                $parts[$i] = self::replaceText($seg, $pairs, true);
            } elseif (preg_match('~^<(script|style|!--)~i', $seg)) {
                continue;
            } else {
                $parts[$i] = self::replaceAttrs($seg, $pairs);
            }
        }
        return implode('', $parts);
    }
}

SgApply::start();
