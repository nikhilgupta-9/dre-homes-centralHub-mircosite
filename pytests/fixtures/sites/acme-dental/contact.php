<?php
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
