'use strict';
const fs = require('fs');
const path = require('path');

// ----------------------------------------------------------------------------
// Realistic micro-site fixtures, written to disk by the tests.
// Each site isolates one situation the scanner must get right.
// ----------------------------------------------------------------------------
const PAGE = (title, body, extraHead = '') =>
  `<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>${title}</title>\n<meta name="description" content="${title} - local business">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n${extraHead}</head>\n<body>\n${body}\n</body>\n</html>\n`;

const SITES = {
  // classic: HTML form -> PHP handler -> mail + MySQL insert + redirect; .sql dump left in the folder
  'acme-dental': {
    'index.html': PAGE('Acme Dental Clinic', `<h1>Acme Dental</h1>
<form id="enquiry" action="contact.php" method="post">
  <input type="text" name="name" placeholder="Your name" required>
  <input type="email" name="email" placeholder="Email" required>
  <input type="tel" name="phone" placeholder="Phone">
  <textarea name="message" placeholder="How can we help?"></textarea>
  <button type="submit" name="submit">Book now</button>
</form>
<footer>Call us: +91 98290 12345 | <a href="mailto:info@acmedental.in">info@acmedental.in</a></footer>`),
    'about.html': '<!DOCTYPE html>\n<html>\n<head><title>About Acme</title></head>\n<body>\n<h1>About us</h1>\n<p>Reach us on <a href="tel:+919829012345">+91 98290 12345</a> or 0141-2345678.</p>\n</body>\n</html>\n',
    'thank-you.html': PAGE('Thank you', '<h1>Thank you, we will call you</h1>'),
    'contact.php': `<?php
include 'inc/db.php';
$to = 'owner@acmedental.in';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = mysqli_real_escape_string($conn, $_POST['name']);
    $email = $_POST['email'];
    $phone = $_POST['phone'];
    $message = $_POST['message'];
    // mail('old-address@nowhere.example', 'commented out', 'x');
    mail($to, 'New enquiry from ' . $name, $message);
    mysqli_query($conn, "INSERT INTO enquiries (name, email, phone, message, created_at) VALUES ('$name', '$email', '$phone', '$message', NOW())");
    header('Location: thank-you.html');
    exit;
}
`,
    'inc/db.php': "<?php\n$conn = mysqli_connect('localhost', 'dbuser', 'S3cretPass!', 'acme_db');\n",
    'backup/acme_db.sql': `-- MySQL dump 10.13
DROP TABLE IF EXISTS \`enquiries\`;
CREATE TABLE \`enquiries\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`name\` varchar(120) DEFAULT NULL,
  \`email\` varchar(150) DEFAULT NULL,
  \`phone\` varchar(20) DEFAULT NULL,
  \`message\` text,
  \`created_at\` datetime DEFAULT NULL,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
INSERT INTO \`enquiries\` VALUES (1,'Rahul Private','rahul.private@example.com','9876500000','Need braces price','2025-01-01 10:00:00');
INSERT INTO \`enquiries\` VALUES (2,'Meena','meena.secret@example.com','9876500001','Whitening?','2025-01-02 11:00:00');
DROP TABLE IF EXISTS \`users\`;
CREATE TABLE \`users\` (
  \`id\` int(11) NOT NULL,
  \`username\` varchar(50) NOT NULL,
  \`password_hash\` varchar(255) NOT NULL,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB;
CREATE TABLE \`services\` (
  \`id\` int(11) NOT NULL,
  \`title\` varchar(100) NOT NULL,
  \`price\` decimal(10,2) DEFAULT NULL
) ENGINE=InnoDB;
`,
  },

  // AJAX form (jQuery), JSON answer, mail only, no database
  'quick-ajax': {
    'index.html': PAGE('Quick Movers', `<h1>Quick Movers</h1>
<form id="contactForm" method="post">
  <input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Send</button>
</form>
<script src="js/jquery.min.js"></script>
<script>
$('#contactForm').on('submit', function (e) {
  e.preventDefault();
  $.ajax({
    type: 'POST',
    url: 'send.php',
    data: $(this).serialize(),
    dataType: 'json',
    success: function (res) {
      if (res.status == 'success') { alert(res.message); } else { alert('Error'); }
    }
  });
});
</script>`),
    'js/jquery.min.js': "/*! jQuery */ $.ajax({type:'POST',url:'lib-must-be-ignored.php'}); $('#contactForm');",
    'send.php': `<?php
header('Content-Type: application/json');
if (empty($_POST['email'])) {
    echo json_encode(['status' => 'error', 'message' => 'Email required']);
    exit;
}
mail('sales@quickmovers.in', 'Lead', $_POST['message']);
echo json_encode(['status' => 'success', 'message' => 'Thanks, we will call you soon']);
`,
  },

  // AJAX form, JS in an external file, handler answers with a variable -> success answer unknown
  'fetch-unknown': {
    'contact.html': PAGE('Fetch Co', `<h1>Contact Fetch Co</h1>
<form class="lead-form" action="process.php" method="post">
  <input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Send</button>
</form>
<div id="msg"></div>
<script src="js/main.js"></script>`),
    'js/main.js': `document.querySelector('.lead-form').addEventListener('submit', function (e) {
  e.preventDefault();
  fetch('process.php', { method: 'POST', body: new FormData(this) })
    .then(function (r) { return r.text(); })
    .then(function (t) { document.getElementById('msg').innerHTML = t; });
});
`,
    'process.php': "<?php\n$msg = '<b>Thanks</b>';\nmail('hi@fetchco.in', 'Lead', $_POST['message']);\necho $msg;\n",
  },

  // things that cannot (or must not) be protected
  'external-forms': {
    'index.html': PAGE('External Forms', `<h1>External forms</h1>
<form action="https://formspree.io/f/xyzabc" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Send</button></form>
<form action="https://acme.us1.list-manage.com/subscribe/post?u=1" method="post"><input type="email" name="EMAIL"><button>Join</button></form>
<form action="mailto:info@example.com" method="post" enctype="text/plain"><input name="name"><textarea name="message"></textarea><button>Mail</button></form>
<form action="login.php" method="post"><input name="user"><input type="password" name="pw"><button>Log in</button></form>
<form action="/search" method="get"><input type="search" name="q"><button>Go</button></form>`),
    'action-empty.html': PAGE('No Action', '<h1>Form without action</h1><form method="post"><input type="email" name="email"><textarea name="message"></textarea><button>Send</button></form>'),
    'login.php': "<?php\nsession_start();\nif (isset($_POST['user'])) { /* ... */ }\n",
  },

  // WordPress: forms come from plugins/themes -> leave to a WordPress-specific solution
  'wp-site': {
    'index.php': "<?php\nrequire __DIR__ . '/wp-blog-header.php';\n",
    'wp-config.php': "<?php\ndefine('DB_NAME', 'wp_db');\ndefine('DB_USER', 'wpuser');\ndefine('DB_PASSWORD', 'wpSecret123');\ndefine('DB_HOST', 'localhost');\n",
    'wp-includes/version.php': "<?php\n$wp_version = '6.4';\n",
    'wp-content/index.php': "<?php\n// Silence is golden.\n",
    'wp-content/plugins/contact-form-7/readme.txt': 'Contact Form 7',
    'wp-content/themes/twentyx/footer.php': `<footer>
<form method="post" action="<?php echo admin_url('admin-post.php'); ?>"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Send</button></form>
<form action="/" method="get"><input type="search" name="s"></form>
</footer>
`,
  },

  // SpamGuard already installed: must be recognised, nothing to do
  'already-protected': {
    'index.html': PAGE('Already Safe', `<h1>Already protected</h1>
<form action="contact.php" method="post"><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Send</button></form>
<script src="/spamguard/spamguard.js" defer></script>`),
    'contact.php': "<?php\nrequire_once __DIR__ . '/spamguard/spamguard.php';\nSpamGuard::guard();\nmail('x@safe.in', 'Enquiry', $_POST['message']);\n",
    'spamguard/spamguard.php': "<?php\n// SpamGuard kit (stub)\nclass SpamGuard { public static function guard() {} }\n",
  },

  // page posts to itself, handler code at the top of the same file
  'self-post': {
    'contact.php': `<?php
$sent = false;
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    mail('hello@selfpost.in', 'Enquiry', $_POST['message']);
    $sent = true;
}
?>
<!DOCTYPE html>
<html lang="en">
<head><title>Contact Self Post</title></head>
<body>
<h1>Contact us today</h1>
<?php if ($sent) { echo '<p>Thanks!</p>'; } ?>
<form method="post" action="<?php echo $_SERVER['PHP_SELF']; ?>">
  <input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Send</button>
</form>
</body>
</html>
`,
  },

  // the form lives in a shared footer include; handler uses root-relative path and a CSV file
  'include-form': {
    'header.php': '<!DOCTYPE html>\n<html lang="en">\n<head><title>Shop</title><meta name="viewport" content="width=device-width"></head>\n<body>\n',
    'index.php': "<?php include 'header.php'; ?>\n<h1>Welcome to our shop, we sell many things</h1>\n<?php include 'footer.php'; ?>\n</body></html>\n",
    'about.php': "<?php include 'header.php'; ?>\n<h1>About our family shop since 1990</h1>\n<?php include 'footer.php'; ?>\n</body></html>\n",
    'footer.php': '<footer>\n<form action="/lead-handler.php" method="post">\n<input name="name"><input type="email" name="email"><input type="tel" name="phone"><button>Call me</button>\n</form>\n</footer>\n',
    'lead-handler.php': "<?php\nif ($_SERVER['REQUEST_METHOD'] === 'POST') {\n    file_put_contents(__DIR__ . '/leads.csv', implode(',', [$_POST['name'], $_POST['email'], $_POST['phone']]) . \"\\n\", FILE_APPEND);\n    header('Location: /index.php?sent=1');\n}\n",
  },

  // form printed by PHP echo -> cannot be edited safely. Also proves the scanner never RUNS site code.
  'php-generated': {
    'index.php': "<?php\nfile_put_contents(__DIR__ . '/EXECUTED.txt', 'the scanner ran PHP code!');\necho '<form method=\"post\" action=\"send.php\"><input name=\"email\"></form>';\n?>\n",
  },

  // a login form and an enquiry form on one page, same handler
  'mixed-handler': {
    'contact.php': `<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['pw'])) { /* login */ } else { mail('a@mixed.in', 'x', $_POST['message']); }
}
?>
<!DOCTYPE html>
<html lang="en">
<head><title>Account and contact</title></head>
<body>
<h1>Account and contact page</h1>
<form method="post"><input name="user"><input type="password" name="pw"><button>Login</button></form>
<form method="post"><input type="email" name="email"><textarea name="message"></textarea><button>Send</button></form>
</body>
</html>
`,
  },

  // nothing useful: images only
  'empty-site': {
    'readme.txt': 'nothing to see here',
  },
};

function writeSite(root, name) {
  const dir = path.join(root, name);
  fs.mkdirSync(dir, { recursive: true });
  for (const [rel, content] of Object.entries(SITES[name])) {
    const f = path.join(dir, rel);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, content);
  }
  if (name === 'empty-site') fs.writeFileSync(path.join(dir, 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 1, 2, 3]));
  return dir;
}

function buildFixtures(root) {
  const out = {};
  for (const name of Object.keys(SITES)) out[name] = writeSite(root, name);
  return out;
}

// ----------------------------------------------------------------------------
// Minimal ZIP writer (stored, no compression) that can write ANY entry name,
// including malicious ones, which normal zip tools refuse to create.
// ----------------------------------------------------------------------------
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** entries: [{name, data(Buffer|string), mode?}] ; mode is the unix st_mode (e.g. 0o120777 = symlink) */
function makeZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf8');
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(String(e.data), 'utf8');
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(0, 8);
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0x21, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, name, data);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE((3 << 8) | 20, 4); // made by: unix
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(0, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0x21, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt16LE(0, 30);
    ch.writeUInt16LE(0, 32);
    ch.writeUInt16LE(0, 34);
    ch.writeUInt16LE(0, 36);
    ch.writeUInt32LE(((e.mode || 0o100644) << 16) >>> 0, 38);
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, name);
    offset += lh.length + name.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

/** Zip a folder the way a Mac does: wrapper folder, __MACOSX junk, .DS_Store, ._ files. */
function zipFolder(dir, destZip, { wrapper = true } = {}) {
  const entries = [];
  const wrap = wrapper ? path.basename(dir) + '/' : '';
  const walkDir = (d, rel) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      const r = rel ? rel + '/' + e.name : e.name;
      if (e.isDirectory()) walkDir(p, r);
      else entries.push({ name: wrap + r, data: fs.readFileSync(p) });
    }
  };
  walkDir(dir, '');
  if (wrapper) {
    entries.push({ name: '__MACOSX/' + wrap + '._index.html', data: Buffer.from([0, 5, 22, 7, 0, 2]) });
    entries.push({ name: wrap + '.DS_Store', data: Buffer.from([0, 0, 0, 1]) });
  }
  fs.writeFileSync(destZip, makeZip(entries));
  return destZip;
}

module.exports = { SITES, buildFixtures, writeSite, makeZip, zipFolder };
