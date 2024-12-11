<?php
include "../function.php";
$nisn = $_GET["nisn"];
$hapus = v_hapus($nisn);
var_dump($hapus);
if($hapus>0){
    echo"
    <script>
    alert('berhasil')
    document.location.href='menampilkan.php'
    </script>
    ";
}

?>
