<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    file_put_contents(__DIR__ . '/leads.csv', implode(',', [$_POST['name'], $_POST['email'], $_POST['phone']]) . "\n", FILE_APPEND);
    header('Location: /index.php?sent=1');
}
