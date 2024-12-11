<?php
include "navbar.php";
include "../function.php";
$nisn = $_GET["nisn"];
$query = "SELECT * FROM kandidat WHERE id_kandidat=$nisn";
$tampil = tampil($query);

if(isset($_POST["submit"])){
    if((v_ubah($_POST,$nisn))>0){
        echo "
        <script>
        alert('berhasil mengubah data');
        document.location.href='menampilkan.php';

        </script>
        ";
        }
        
    }
?>
<form class="container d-flex flex-column align-items-center mt-5
w-50 p-5 shadow-4"
action="" method="post">
    <h3>MENGUBAH KANDIDAT SISWA</h3>
    <?php foreach($tampil as $t):?>
  <!-- id_kandidat input -->
  <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example1" class="form-control" 
    name="id_kandidat" value="<?php echo $t["id_kandidat"];?>"/>
    <label class="form-label" for="form1Example1">id_kandidat</label>
  </div>
  <!-- fullname input -->
  <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example2" class="form-control" 
    name="fullname" value="<?php echo $t["fullname"];?>"/>
    <label class="form-label" for="form1Example2">fullname</label>
  </div>
  <!-- foto input -->
  <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example2" class="form-control" 
    name="foto" value="<?php echo $t["foto"];?>"/>
    <label class="form-label" for="form1Example2">foto</label>
  </div>
  <!-- visi input -->
  <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example2" class="form-control"
    name="visi" value="<?php echo $t["visi"];?>" />
    <label class="form-label" for="form1Example2">visi</label>
  </div>
   <!-- misi input -->
   <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example2" class="form-control"
    name="misi" value="<?php echo $t["misi"];?>" />
    <label class="form-label" for="form1Example2">misi</label>
  </div>
   <!-- suara input -->
   <div data-mdb-input-init class="form-outline mb-4">
    <input type="text" id="form1Example2" class="form-control"
    name="suara" value="<?php echo $t["suara"];?>" />
    <label class="form-label" for="form1Example2">suara</label>
  </div>


  <!-- Submit button -->
    <button data-mdb-ripple-init type="submit" name="submit" class="btn btn-primary btn-block w-25">
    submit    
    </button>
    <?php endforeach;?>
</form>