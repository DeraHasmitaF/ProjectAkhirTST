<?php
session_start();
include "navbar.php";
include "function.php";
include "VoteAsses.php"; // Pastikan untuk menyertakan kelas ini

$conn = mysqli_connect("localhost:3307", "root", "", "vote1");
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}


function generateToken($length = 32) {
    return bin2hex(random_bytes($length)); 
}

// Fungsi untuk mengenkripsi token
function encryptToken($token) {
    $encryption_key = bin2hex(random_bytes(32)); 
    return openssl_encrypt($token, 'AES-128-ECB', $encryption_key);
}

// Fungsi untuk memvalidasi reCAPTCHA
function validateRecaptcha($recaptchaResponse) {
    $secretKey = '6LdC1ZEqAAAAALKG5UXhh7vdJf93klGSNmdE_bv6';
    $response = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$secretKey&response=$recaptchaResponse");
    $responseKeys = json_decode($response, true);
    return intval($responseKeys["success"]) === 1;
}

if (isset($_POST["submit"])) {
    $nisn = $_POST["nisn"];
    $auth_code = $_POST["auth_code"]; 
    $recaptchaResponse = $_POST['g-recaptcha-response']; 

    // Validasi reCAPTCHA
    if (!validateRecaptcha($recaptchaResponse)) {
        echo "<script>alert('reCAPTCHA validation failed. Please try again.'); document.location.href='indeks2.php';</script>";
        exit;
    }

    // Array untuk menyimpan NIM dan kode autentikasi yang valid
    $valid_auth_codes = [
        '28982972' => 'password123', // NIM => Kode Autentikasi
        '287997287' => '456'
    ];
  
    // Periksa apakah NIM dan kode autentikasi valid
    if (array_key_exists($nisn, $valid_auth_codes) && $valid_auth_codes[$nisn] === $auth_code) {
    
        $_SESSION["nisn"] = $nisn;
        $token = generateToken(); // Generate token
        $encryptedToken = encryptToken($token); // Enkripsi token
        $timestamp = time(); // Ambil timestamp saat ini
        $stmt = $conn->prepare("INSERT INTO tokens (nisn, token, timestamp) VALUES (?, ?, NOW())");
        $stmt->bind_param("ss", $nisn, $encryptedToken);
        $stmt->close();

        try {
            $wsdl = "http://localhost/wselder/VoteAsses.wsdl";
            $client = new SoapClient($wsdl);
            $voteAsses = new VoteAsses();
            $message = $voteAsses->getVote($nisn); // Menggunakan NIM untuk mendapatkan pesan
            
            // Cek status $tugasLMS
            if ($message === "Silahkan melakukan voting!") {
                echo "<script>alert('Silahkan melakukan voting'); document.location.href='voter/vote.php?token=$token';</script>";
            } else {
                echo "<script>alert('$message'); document.location.href='indeks2.php';</script>";
            }
        } catch (Exception $e) {
            echo "<script>alert('Terjadi kesalahan saat memanggil layanan voting.'); document.location.href='indeks2.php';</script>";
        }
    } else {
        echo "<script>alert('NIM atau kode autentikasi salah. Silakan coba lagi.'); document.location.href='indeks2.php';</script>";
    }
}

mysqli_close($conn); // Menutup koneksi database
?>

<div class="container min-vh-100 d-flex justify-content-center align-items-center">
    <form action="" method="post" class="d-flex flex-column gap-2 shadow-4 p-5">
        <label for="nisn" class="me-2">NIM</label>
        <input type="text" id="nisn" name="nisn" placeholder="Masukkan NIM" style="width: 500px;">
        
        <label for="auth_code" class="me-2">Kode Autentikasi</label>
        <input type="text" id="auth_code" name="auth_code" placeholder="Masukkan Kode Autentikasi" style="width: 500px;">
        
        <div class="g-recaptcha" data-sitekey="6LdC1ZEqAAAAAI-aUIJZ2AjXlFgRLizjYEJTj20-"></div> <!-- Tambahkan reCAPTCHA di sini -->
        
        <button class="btn btn-primary" type="submit" name="submit"> Lakukan Voting</button>
    </form>
</div>

<script src="https://www.google.com/recaptcha/api.js" async defer></script>