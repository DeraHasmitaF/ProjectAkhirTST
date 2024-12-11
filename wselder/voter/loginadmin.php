<?php
session_start();
include "navbar.php";
include "../function.php";
if(isset($_POST["submit"])){
$input_fullname = $_POST["fullname"];
$input_password = $_POST["password"];
$q_user = "SELECT * FROM admin WHERE fullname='$input_fullname'";
$data_user = a_login($q_user);
$fullname = $data_user["fullname"];
$password = $data_user["password"];
    if($input_fullname==$fullname && $input_password==$password){
        echo"
            <script>
            alert('selamat datang')
            document.location.href='menampilkan.php';
            </script>
        ";
    }
}
?>
<div class="container min-vh-100 d-flex justify-content-center 
align-items-center" >
        <form action="" method="post" 
        class="d-flex flex-column gap-2 shadow-4 p-5">

            <label for="fullname" class="me-2">USERNAME</label>
            <input type="text" id="fullname" name="fullname" 
            placeholder="masukan username" style="width: 500px;">
            
            <label for="password" class="me-2">PASSWORD</label>
            <input type="pasword" id="password" name="password" 
            placeholder="masukan id" style="width: 500px;">

            <button class="btn btn-primary" type="submit" name="submit">
            MASUK</button>
            
        </form>
</div>
