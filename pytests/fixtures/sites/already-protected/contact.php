<?php
require_once __DIR__ . '/spamguard/spamguard.php';
SpamGuard::guard();
mail('x@safe.in', 'Enquiry', $_POST['message']);
