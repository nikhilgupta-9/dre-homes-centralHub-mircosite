<?php
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
