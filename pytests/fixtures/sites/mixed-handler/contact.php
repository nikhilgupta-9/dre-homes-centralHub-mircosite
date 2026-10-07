<?php
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
