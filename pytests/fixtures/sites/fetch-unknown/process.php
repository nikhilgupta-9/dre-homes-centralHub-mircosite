<?php
$msg = '<b>Thanks</b>';
mail('hi@fetchco.in', 'Lead', $_POST['message']);
echo $msg;
