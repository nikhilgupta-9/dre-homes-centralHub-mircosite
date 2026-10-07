<?php
header('Content-Type: application/json');
if (empty($_POST['email'])) {
    echo json_encode(['status' => 'error', 'message' => 'Email required']);
    exit;
}
mail('sales@quickmovers.in', 'Lead', $_POST['message']);
echo json_encode(['status' => 'success', 'message' => 'Thanks, we will call you soon']);
