<?php
file_put_contents(__DIR__ . '/EXECUTED.txt', 'the scanner ran PHP code!');
echo '<form method="post" action="send.php"><input name="email"></form>';
?>
