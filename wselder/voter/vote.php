<?php
session_start();
include "navbar.php";
include "../function.php";

if (!isset($_SESSION["nisn"])) {
    header("Location: ../index.php");
    exit(); // Always use exit after header redirection
}

$nisn = (int)$_SESSION["nisn"];
$query = "SELECT * FROM kandidat";
$tampil = tampil($query);
$message = ""; // Initialize message variable

if (isset($_POST["submit"])) {
    $voteResult = vote($nisn, $_POST);
    if ($voteResult > 0) {
        // Vote successful, set success message
        $message = "Voting berhasil";
        echo "
        <script>
        alert('Selamat $message');
        document.location.href='../indeks2.php'; // Redirect to index.php after voting
        </script>
        ";
        exit(); // Ensure no further code is executed after the redirect
    } else {
        // Vote failed, set error message
        $message = "Voting gagal. Silakan coba lagi.";
        echo "
        <script>
        alert('$message');
        document.location.href='../indeks2.php'; // Redirect to an error page or stay on the same page
        </script>
        ";
        exit(); // Ensure no further code is executed after the redirect
    }
}

// Logic to get voting history
$histories = [];
if (isset($_POST["getHistory"])) {
    try {
        $wsdl = "http://localhost/wselder/VoteAsses.wsdl";
        $client = new SoapClient($wsdl);
        $histories = $client->getHistories(); 
    } catch (SoapFault $fault) {
        echo "Error: " . $fault->getMessage();
    }
}

// Validasi token dan timestamp
if (isset($_GET['token'])) {
    $token = $_GET['token'];
    $encryption_key = bin2hex(random_bytes(32)); // Ganti dengan kunci enkripsi Anda
    $decryptedToken = openssl_decrypt($token, 'AES-128-ECB', $encryption_key);
    
    // Cek timestamp
    $stmt = $conn->prepare("SELECT timestamp FROM tokens WHERE token = ?");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $stmt->bind_result($timestamp);
    $stmt->fetch();
    $stmt->close();

    if ($timestamp && (time() - $timestamp > 300)) { // 300 detik = 5 menit
        // Token expired
        session_destroy();
        header("Location: ../indeks2.php");
        exit();
    }
}
?>


<div class="d-flex container gap-5 min-vh-100 align-items-center">
    <?php foreach ($tampil as $t): ?>
        <div class="card gap-2">
            <form action="" method="post">
                <div class="bg-image hover-overlay" data-mdb-ripple-init data-mdb-ripple-color="light">
                    <img src="../img/<?php echo $t["foto"] ?>" class="img-fluid" />
                    <a href="#!">
                        <div class="mask" style="background-color: rgba(251, 251, 251, 0.15);"></div>
                    </a>
                </div>
                <div class="card-body">
                    <h5 class="card-title"><?php echo $t["fullname"] ?></h5>
                    <p class="card-text">visi: <?php echo $t["visi"] ?></p>
                    <p class="card-text">misi: <?php echo $t["misi"] ?></p>
                    <button class="btn btn-primary" name="submit" value="<?php echo $t["suara"]; ?>">
                        PILIH!
                    </button>
                </div>
            </form>
        </div>
    <?php endforeach; ?>
    
    <form action="" method="post" class="mt-4">
        <button class="btn btn-secondary" name="getHistory">Get History</button>
    </form>
</div>

<?php if (!empty($histories)): ?>
    <div class="container mt-5">
        <h3>Riwayat Voting</h3>
        <ul class="list-group">
            <?php foreach ($histories as $history): ?>
                <li class="list-group-item">
                    NIM: <?php echo $history->nim; ?> - Pilihan: <?php echo $history->pilihan; ?>
                </li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>