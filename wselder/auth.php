<?php
require 'vendor/autoload.php'; // Pastikan untuk memuat autoloader Composer
use \Firebase\JWT\JWT;

$conn = mysqli_connect("localhost:3307", "root", "", "vote1");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $query = "SELECT * FROM users WHERE username = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        // Verifikasi password
        if (password_verify($password, $user['password'])) {
            // Membuat token
            $payload = [
                'iat' => time(),
                'exp' => time() + 3600, // Token valid selama 1 jam
                'id' => $user['id'],
                'username' => $user['username']
            ];

            $jwt = JWT::encode($payload, 'secret_key'); // Ganti 'secret_key' dengan kunci rahasia Anda
            echo json_encode(['token' => $jwt]);
        } else {
            echo json_encode(['error' => 'Invalid credentials']);
        }
    } else {
        echo json_encode(['error' => 'User  not found']);
    }
}
?>