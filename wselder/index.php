<?php
session_start();
include "navbar.php";
include "function.php";
include "VoteAsses.php"; // Pastikan untuk menyertakan kelas ini

$conn = mysqli_connect("localhost:3307", "root", "", "vote1");

if (isset($_POST["submit"])) {
    $nisn = $_POST["nisn"];
    $voteAsses = new VoteAsses();

    // Inisialisasi nilai LMS
    $tugasLMS = false; 
    if ($nisn === '28982972') {
        $tugasLMS = true; 
    } elseif ($nisn === '287997287') {
        $tugasLMS = false; // False untuk NIM ini
    } else {
        echo "
        <script>
        alert('NIM tidak dikenal');
        document.location.href='index.php';
        </script>
        ";
        exit; 
    }

    // Panggil layanan SOAP untuk mendapatkan suara
    try {
        $wsdl = "http://localhost/wselder/VoteAsses.wsdl";
        $client = new SoapClient($wsdl);
        $vote = $client->getVote($tugasLMS);

        // Periksa nilai LMS dari respons SOAP
        if ($vote) {
            $_SESSION["nisn"] = $nisn;
            $message = $voteAsses->getVote($tugasLMS); // Mengambil pesan dari metode getVote
            echo "
            <script>
            alert('Selamat datang, pengguna dengan NIM $nisn! $message');
            document.location.href='voter/vote.php';
            </script>
            ";
        } else {
            echo "
            <script>
            alert('" . $voteAsses->getVote(false) . "');
            document.location.href='index.php';
            </script>
            ";
        }
    } catch (SoapFault $fault) {
        echo "
        <script>
        alert('Kesalahan saat menghubungi layanan web: " . $fault->getMessage() . "');
        document.location.href='index.php';
        </script>
        ";
        exit; // Hentikan eksekusi jika terjadi kesalahan SOAP
    }
}
?>

<div class="container min-vh-100 d-flex justify-content-center align-items-center">
    <form action="" method="post" class="d-flex flex-column gap-2 shadow-4 p-5">
        <label for="nisn" class="me-2">NIM</label>
        <input type="text" id="nisn" name="nisn" placeholder="Masukkan NIM" style="width: 500px;">
        <button class="btn btn-primary" type="submit" name="submit">Lakukan Voting</button>
    </form>
</div>