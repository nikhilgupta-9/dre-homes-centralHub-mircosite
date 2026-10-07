<?php
/**
 * SpamGuard admin page: Real / Suspicious / Spam enquiries + file integrity.
 * Open:  https://yoursite.com/spamguard/spam-admin.php   (password from make-config.php)
 */
define('SG_LIB', true);
require __DIR__ . '/spamguard.php';
require __DIR__ . '/integrity.php';

$cfg = SpamGuard::config();
try {
    date_default_timezone_set($cfg['timezone'] ?: 'Asia/Kolkata');
} catch (\Throwable $e) {
    date_default_timezone_set('UTC');
}

$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow');

session_name('sgadm');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/') ?: '/',
    'secure' => $https,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

function e($s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$self = basename($_SERVER['SCRIPT_NAME'] ?? 'spam-admin.php');

function page(string $title, string $body): void
{
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<meta name="robots" content="noindex,nofollow"><title>' . e($title) . '</title><style>'
        . ':root{--bg:#f4f5f7;--card:#fff;--ink:#1d2330;--mut:#6b7385;--line:#e3e6ec;--ok:#14803c;--warn:#b45309;--bad:#b91c1c;--acc:#2b5fd9}'
        . '@media(prefers-color-scheme:dark){:root{--bg:#12151c;--card:#1b2029;--ink:#e8ebf2;--mut:#98a1b5;--line:#2a3140;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--acc:#7ea2ff}}'
        . '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}'
        . '.wrap{max-width:60rem;margin:0 auto;padding:1rem}h1{font-size:1.25rem;margin:.2rem 0 1rem}'
        . '.top{display:flex;justify-content:space-between;align-items:center;gap:.5rem;flex-wrap:wrap}'
        . '.tabs{display:flex;gap:.4rem;flex-wrap:wrap;margin:.5rem 0 1rem}.tabs a{padding:.45rem .8rem;border-radius:999px;background:var(--card);border:1px solid var(--line);color:var(--ink);text-decoration:none}'
        . '.tabs a.on{background:var(--acc);border-color:var(--acc);color:#fff}.tabs b{opacity:.75;font-weight:600;margin-left:.3rem}'
        . '.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:.9rem 1rem;margin-bottom:.7rem}'
        . '.row{display:flex;justify-content:space-between;gap:.6rem;flex-wrap:wrap}.mut{color:var(--mut);font-size:.85rem}'
        . '.badge{display:inline-block;border-radius:6px;padding:.05rem .45rem;font-size:.8rem;font-weight:700;border:1px solid currentColor}'
        . '.real{color:var(--ok)}.suspicious{color:var(--warn)}.spam{color:var(--bad)}'
        . 'dl{margin:.5rem 0;display:grid;grid-template-columns:max-content 1fr;gap:.15rem .8rem}dt{color:var(--mut)}dd{margin:0;word-break:break-word;white-space:pre-wrap}'
        . 'details{margin-top:.4rem}summary{cursor:pointer;color:var(--mut);font-size:.85rem}ul.r{margin:.3rem 0 0;padding-left:1.2rem;font-size:.85rem}'
        . 'form.inl{display:inline}button,input[type=submit]{font:inherit;cursor:pointer;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink);padding:.35rem .7rem}'
        . 'button.go{background:var(--acc);border-color:var(--acc);color:#fff}button.no{color:var(--bad)}'
        . 'input[type=text],input[type=password]{font:inherit;padding:.45rem .6rem;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink);max-width:100%}'
        . '.flash{background:var(--card);border-left:4px solid var(--acc);padding:.6rem .8rem;margin-bottom:.8rem;border-radius:6px}'
        . '.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:.5rem;margin-bottom:.8rem}.stats div{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:.6rem .8rem}.stats strong{display:block;font-size:1.4rem}'
        . '</style></head><body><div class="wrap">' . $body . '</div></body></html>';
}

$pdo = SpamGuard::pdo();
if ($cfg['admin_password_hash'] === '') {
    page('SpamGuard', '<h1>SpamGuard</h1><div class="card">Admin password is not set. Run <code>php make-config.php</code> once (see README).</div>');
    exit;
}
if (!$pdo) {
    page('SpamGuard', '<h1>SpamGuard</h1><div class="card">Storage is not available (PHP needs <code>pdo_sqlite</code> and a writable data folder). Open <code>selftest.php</code> for details.</div>');
    exit;
}

// ------------------------------------------------------------------ login
if (empty($_SESSION['ok'])) {
    $err = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        $ip = SpamGuard::clientIp();
        $pdo->prepare('DELETE FROM logins WHERE ts < ?')->execute([time() - 900]);
        $st = $pdo->prepare('SELECT COUNT(*) FROM logins WHERE ip = ?');
        $st->execute([$ip]);
        if ((int) $st->fetchColumn() >= 5) {
            $err = 'Too many wrong attempts. Try again in 15 minutes.';
        } elseif (SpamGuard::verifyPassword((string) $_POST['password'], (string) $cfg['admin_password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['ok'] = 1;
            $_SESSION['csrf'] = bin2hex(random_bytes(16));
            header('Location: ' . $self);
            exit;
        } else {
            $pdo->prepare('INSERT INTO logins(ip, ts) VALUES(?, ?)')->execute([$ip, time()]);
            usleep(400000);
            $err = 'Wrong password.';
        }
    }
    page('SpamGuard login', '<h1>SpamGuard</h1><form method="post" class="card"><p>Admin password</p>'
        . ($err !== '' ? '<p class="spam">' . e($err) . '</p>' : '')
        . '<p><input type="password" name="password" autofocus autocomplete="current-password"></p>'
        . '<p><button class="go" type="submit">Log in</button></p></form>');
    exit;
}

// ------------------------------------------------------------------ actions (POST + CSRF)
$tab = $_GET['tab'] ?? 'real';
if (!in_array($tab, ['real', 'suspicious', 'spam', 'integrity'], true)) {
    $tab = 'real';
}
$q = trim((string) ($_GET['q'] ?? ''));
$pageNo = max(1, (int) ($_GET['p'] ?? 1));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals((string) $_SESSION['csrf'], (string) ($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        exit('Bad request');
    }
    $act = (string) ($_POST['action'] ?? '');
    $id = (int) ($_POST['id'] ?? 0);
    $flash = '';
    if ($act === 'logout') {
        $_SESSION = [];
        session_destroy();
        header('Location: ' . $self);
        exit;
    } elseif ($act === 'mark_real' || $act === 'mark_spam') {
        $pdo->prepare('UPDATE submissions SET override = ? WHERE id = ?')->execute([$act === 'mark_real' ? 'real' : 'spam', $id]);
        $flash = 'Enquiry #' . $id . ' moved to ' . ($act === 'mark_real' ? 'Real' : 'Spam') . '.';
    } elseif ($act === 'reset') {
        $pdo->prepare('UPDATE submissions SET override = NULL WHERE id = ?')->execute([$id]);
        $flash = 'Enquiry #' . $id . ' reset to the automatic verdict.';
    } elseif ($act === 'delete') {
        $pdo->prepare('DELETE FROM submissions WHERE id = ?')->execute([$id]);
        $flash = 'Enquiry #' . $id . ' deleted.';
    } elseif ($act === 'delete_all_spam') {
        if (!empty($_POST['sure'])) {
            $n = $pdo->exec("DELETE FROM submissions WHERE COALESCE(override, status) = 'spam'");
            $flash = $n . ' spam enquiries deleted.';
        } else {
            $flash = 'Tick the box to confirm deleting all spam.';
        }
    } elseif ($act === 'integrity_baseline') {
        $r = SgIntegrity::baseline();
        $flash = $r['ok'] ? 'Baseline saved for ' . $r['files'] . ' files. Future changes will be reported.' : 'Could not save baseline (data folder not writable).';
    } elseif ($act === 'integrity_check') {
        $r = SgIntegrity::check();
        $flash = 'Check finished: ' . SgIntegrity::problems($r) . ' item(s) need attention.';
    }
    $_SESSION['flash'] = $flash;
    header('Location: ' . $self . '?tab=' . $tab . ($q !== '' ? '&q=' . rawurlencode($q) : '') . ($pageNo > 1 ? '&p=' . $pageNo : ''));
    exit;
}

// ------------------------------------------------------------------ CSV export
if (isset($_GET['export']) && $tab !== 'integrity') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="enquiries-' . $tab . '-' . date('Ymd') . '.csv"');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");
    $safe = function ($v) {
        $v = (string) $v;
        return ($v !== '' && strpos("=+-@\t\r", $v[0]) !== false) ? "'" . $v : $v;
    };
    fputcsv($out, ['ID', 'Time', 'Status', 'Score', 'Name', 'Email', 'Phone', 'Details', 'IP', 'Ad source', 'Campaign', 'Click ID', 'Page']);
    $st = $pdo->prepare("SELECT * FROM submissions WHERE COALESCE(override, status) = ? ORDER BY id DESC LIMIT 20000");
    $st->execute([$tab]);
    foreach ($st as $r) {
        $fields = json_decode((string) $r['fields'], true) ?: [];
        $det = [];
        foreach ($fields as $k => $v) {
            $det[] = $k . ': ' . $v;
        }
        fputcsv($out, array_map($safe, [
            $r['id'], date('Y-m-d H:i:s', (int) $r['ts']), $r['override'] ?: $r['status'], $r['score'], $r['name'], $r['email'],
            $r['phone'], implode(' | ', $det), $r['ip'], $r['utm_source'], $r['utm_campaign'], $r['gclid'], $r['page'],
        ]));
    }
    exit;
}

// ------------------------------------------------------------------ view
$csrf = (string) $_SESSION['csrf'];
$flash = (string) ($_SESSION['flash'] ?? '');
unset($_SESSION['flash']);

$counts = ['real' => 0, 'suspicious' => 0, 'spam' => 0];
foreach ($pdo->query('SELECT COALESCE(override, status) AS s, COUNT(*) AS n FROM submissions GROUP BY s') as $r) {
    $counts[$r['s']] = (int) $r['n'];
}
$last24 = ['real' => 0, 'suspicious' => 0, 'spam' => 0];
$st = $pdo->prepare('SELECT COALESCE(override, status) AS s, COUNT(*) AS n FROM submissions WHERE ts > ? GROUP BY s');
$st->execute([time() - 86400]);
foreach ($st as $r) {
    $last24[$r['s']] = (int) $r['n'];
}

$h = '<div class="top"><h1>SpamGuard &middot; ' . e($cfg['site_id']) . '</h1>'
    . '<form method="post" class="inl"><input type="hidden" name="csrf" value="' . e($csrf) . '"><input type="hidden" name="action" value="logout"><button>Log out</button></form></div>';
if ($flash !== '') {
    $h .= '<div class="flash">' . e($flash) . '</div>';
}
$h .= '<div class="stats"><div><span class="mut">Last 24 hours</span><strong>'
    . '<span class="real">' . $last24['real'] . '</span> / <span class="suspicious">' . $last24['suspicious'] . '</span> / <span class="spam">' . $last24['spam'] . '</span></strong>'
    . '<span class="mut">real / suspicious / spam</span></div>'
    . '<div><span class="mut">Spam blocked, all time</span><strong class="spam">' . $counts['spam'] . '</strong></div>'
    . '<div><span class="mut">Real leads, all time</span><strong class="real">' . $counts['real'] . '</strong></div></div>';

$h .= '<div class="tabs">';
foreach (['real' => 'Real', 'suspicious' => 'Suspicious', 'spam' => 'Spam'] as $k => $label) {
    $h .= '<a class="' . ($tab === $k ? 'on' : '') . '" href="?tab=' . $k . '">' . $label . '<b>' . $counts[$k] . '</b></a>';
}
$h .= '<a class="' . ($tab === 'integrity' ? 'on' : '') . '" href="?tab=integrity">File security</a></div>';

if ($tab === 'integrity') {
    $info = SgIntegrity::baselineInfo();
    $last = SgIntegrity::last();
    $h .= '<div class="card"><p>This watches the site\'s PHP/HTML/JS files for changes and for hacker code patterns. '
        . 'Click <b>Set baseline</b> only when you know the site is clean.</p><p class="mut">'
        . ($info ? 'Baseline: ' . $info['files'] . ' files, saved ' . e(date('d M Y H:i', $info['created'])) : 'No baseline saved yet.') . '</p>'
        . '<form method="post" class="inl"><input type="hidden" name="csrf" value="' . e($csrf) . '"><input type="hidden" name="tab" value="integrity">'
        . '<input type="hidden" name="action" value="integrity_check"><button class="go">Check now</button></form> '
        . '<form method="post" class="inl"><input type="hidden" name="csrf" value="' . e($csrf) . '"><input type="hidden" name="action" value="integrity_baseline"><button>Set baseline</button></form></div>';
    if ($last) {
        $h .= '<div class="card"><b>Last check:</b> ' . e(date('d M Y H:i', (int) $last['time'])) . ' &middot; ' . (int) $last['files'] . ' files'
            . (!$last['has_baseline'] ? '<p class="suspicious">No baseline yet, so only the code-pattern scan ran.</p>' : '');
        $groups = ['changed' => ['Changed files', 'suspicious'], 'added' => ['New files', 'suspicious'], 'removed' => ['Deleted files', 'suspicious']];
        $any = false;
        foreach ($groups as $k => $meta) {
            if ($last[$k]) {
                $any = true;
                $h .= '<p class="' . $meta[1] . '"><b>' . $meta[0] . ' (' . count($last[$k]) . ')</b></p><ul class="r">';
                foreach ($last[$k] as $p) {
                    $h .= '<li>' . e($p) . '</li>';
                }
                $h .= '</ul>';
            }
        }
        if ($last['findings']) {
            $any = true;
            $h .= '<p class="spam"><b>Suspicious code (' . count($last['findings']) . ')</b> <span class="mut">pattern matches can include false alarms, review each file</span></p><ul class="r">';
            foreach ($last['findings'] as $f) {
                $h .= '<li><span class="badge ' . ($f['severity'] === 'high' ? 'spam' : 'suspicious') . '">' . e($f['severity']) . '</span> '
                    . e($f['path']) . ($f['line'] ? ':' . (int) $f['line'] : '') . ' &mdash; ' . e($f['rule']) . '</li>';
            }
            $h .= '</ul>';
        }
        if (!$any) {
            $h .= '<p class="real"><b>All clear.</b> No changes and no suspicious patterns.</p>';
        }
        $h .= '</div>';
    }
    page('SpamGuard', $h);
    exit;
}

// list
$where = "COALESCE(override, status) = :s";
$args = [':s' => $tab];
if ($q !== '') {
    $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $q) . '%';
    $where .= " AND (name LIKE :q ESCAPE '\\' OR email LIKE :q ESCAPE '\\' OR phone LIKE :q ESCAPE '\\' OR ip LIKE :q ESCAPE '\\' OR fields LIKE :q ESCAPE '\\' OR utm_campaign LIKE :q ESCAPE '\\')";
    $args[':q'] = $like;
}
$per = 30;
$st = $pdo->prepare("SELECT COUNT(*) FROM submissions WHERE $where");
$st->execute($args);
$total = (int) $st->fetchColumn();
$pages = max(1, (int) ceil($total / $per));
$pageNo = min($pageNo, $pages);
$st = $pdo->prepare("SELECT * FROM submissions WHERE $where ORDER BY id DESC LIMIT $per OFFSET " . (($pageNo - 1) * $per));
$st->execute($args);

$h .= '<form method="get" class="card row"><input type="hidden" name="tab" value="' . e($tab) . '">'
    . '<span><input type="text" name="q" value="' . e($q) . '" placeholder="Search name, email, phone, IP, text"> <button class="go">Search</button></span>'
    . '<span><a class="mut" href="?tab=' . e($tab) . '&amp;export=1">Download CSV</a></span></form>';

$tabNote = [
    'real' => 'Looks like genuine enquiries.',
    'suspicious' => 'Not sure. Please review: use "Real lead" or "Spam" so the list stays clean.',
    'spam' => 'Blocked. Check "why" if a real person landed here and press "Real lead".',
];
$h .= '<p class="mut">' . e($tabNote[$tab]) . ' &middot; ' . $total . ' result(s)</p>';

$n = 0;
foreach ($st as $r) {
    $n++;
    $eff = $r['override'] ?: $r['status'];
    $fields = json_decode((string) $r['fields'], true) ?: [];
    $reasons = json_decode((string) $r['reasons'], true) ?: [];
    $src = trim($r['utm_source'] . ' ' . $r['utm_campaign']);
    $h .= '<div class="card"><div class="row"><span><b>' . e($r['name'] ?: ($r['email'] ?: 'Enquiry')) . '</b> '
        . '<span class="badge ' . e($eff) . '">' . e(strtoupper($eff)) . ' &middot; score ' . (int) $r['score'] . '</span>'
        . ($r['override'] ? ' <span class="mut">(set by you)</span>' : '') . '</span>'
        . '<span class="mut">#' . (int) $r['id'] . ' &middot; ' . e(date('d M Y, H:i', (int) $r['ts'])) . '</span></div><dl>';
    foreach ($fields as $k => $v) {
        if ($v !== '') {
            $h .= '<dt>' . e($k) . '</dt><dd>' . e($v) . '</dd>';
        }
    }
    $h .= '<dt>IP</dt><dd>' . e($r['ip']) . '</dd>';
    if ($src !== '' || $r['gclid'] !== '') {
        $h .= '<dt>Ad source</dt><dd>' . e($src) . ($r['gclid'] !== '' ? ' (Google click)' : '') . '</dd>';
    }
    if ($r['page'] !== '') {
        $h .= '<dt>Page</dt><dd>' . e($r['page']) . '</dd>';
    }
    $h .= '</dl>';
    if ($reasons) {
        $h .= '<details><summary>Why this verdict</summary><ul class="r">';
        foreach ($reasons as $why) {
            $h .= '<li>' . e($why) . '</li>';
        }
        $h .= '</ul></details>';
    }
    $btn = function (string $action, string $label, string $cls = '') use ($r, $csrf, $tab, $q, $pageNo) {
        return '<form method="post" action="?tab=' . e($tab) . ($q !== '' ? '&amp;q=' . e(rawurlencode($q)) : '') . ($pageNo > 1 ? '&amp;p=' . $pageNo : '') . '" class="inl">'
            . '<input type="hidden" name="csrf" value="' . e($csrf) . '"><input type="hidden" name="id" value="' . (int) $r['id'] . '">'
            . '<input type="hidden" name="action" value="' . e($action) . '"><button class="' . e($cls) . '">' . e($label) . '</button></form> ';
    };
    $h .= '<p>';
    if ($eff !== 'real') {
        $h .= $btn('mark_real', 'Real lead', 'go');
    }
    if ($eff !== 'spam') {
        $h .= $btn('mark_spam', 'Spam', 'no');
    }
    if ($r['override']) {
        $h .= $btn('reset', 'Undo my choice');
    }
    $h .= $btn('delete', 'Delete', 'no') . '</p></div>';
}
if ($n === 0) {
    $h .= '<div class="card mut">Nothing here yet.</div>';
}

$base = '?tab=' . e($tab) . ($q !== '' ? '&amp;q=' . e(rawurlencode($q)) : '');
if ($pages > 1) {
    $h .= '<p class="mut">Page ' . $pageNo . ' of ' . $pages . ' &middot; '
        . ($pageNo > 1 ? '<a href="' . $base . '&amp;p=' . ($pageNo - 1) . '">&larr; Newer</a> ' : '')
        . ($pageNo < $pages ? '<a href="' . $base . '&amp;p=' . ($pageNo + 1) . '">Older &rarr;</a>' : '') . '</p>';
}
if ($tab === 'spam' && $counts['spam'] > 0) {
    $h .= '<form method="post" class="card"><input type="hidden" name="csrf" value="' . e($csrf) . '"><input type="hidden" name="action" value="delete_all_spam">'
        . '<label><input type="checkbox" name="sure" value="1"> Yes, permanently delete all spam</label> <button class="no">Delete all spam</button></form>';
}
page('SpamGuard', $h);
