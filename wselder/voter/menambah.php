<?php
include "navbar.php";
include "../function.php";
if(isset($_POST["submit"])){
    if((v_tambah($_POST))>0){
        echo "
        <script>
        alert('berhasil');
        document.location.href='menampilkan.php';
        </script>
        ";
        }
    }
//token
// $acak = random_bytes(5);
// $token = bin2hex($acak);
?>
<form class="container min-vh-100 d-flex flex-column align-items-center mt-5"
action="" method="post">
    <h3>TAMBAH DATA KANDIDAT</h3>
  <!-- nisn input -->
  <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example1" class="form-control" 
    name="id_kandidat"/>
    <label class="form-label" for="form1Example1">id_kandidat</label>
  </div>
  <!-- fullname input -->
  <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example2" class="form-control" 
    name="fullname"/>
    <label class="form-label" for="form1Example2">fullname</label>
  </div>
  <!-- kelas foto -->
  <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example2" class="form-control" 
    name="foto"/>
    <label class="form-label" for="form1Example2">foto</label>
  </div>
  <!-- token visi -->
  <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example2" class="form-control"
    name="visi"/>
    <label class="form-label" for="form1Example2">visi</label>
  </div>
  <!-- token misi -->
  <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example2" class="form-control"
    name="misi"/>
    <label class="form-label" for="form1Example2">misi</label>
  </div><!-- token suara -->
  <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example2" class="form-control"
    name="suara"/>
    <label class="form-label" for="form1Example2">suara</label>
  </div>


  <!-- Submit button -->
    <button data-mdb-ripple-init type="submit" name="submit" class="btn btn-primary btn-block w-25">
    submit    
    </button>

</form>