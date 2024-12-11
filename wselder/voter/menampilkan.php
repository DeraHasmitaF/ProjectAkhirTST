<?php
include "navbar.php";
include "../function.php";
$query = "SELECT * FROM kandidat";
$tampil = tampil($query);

//hapus

?>
<button class="btn btn-success mt-5 ms-5 ms-5 ">
    <a class=" text-light text-decoration-none" href="menambah.php">
        tambah data
    </a>    
</button>
<table class="table mx-auto mt-5  shadow-4 w-75">
  <thead>
    <tr>
      <th scope="col">id</th>
      <th scope="col">fullname</th>
      <th scope="col">foto</th>
      <th scope="col">visi</th>
      <th scope="col">misi</th>
      <th scope="col">suara</th>
      <th scope="col">aksi</th>
    </tr>
  </thead>
  <tbody>
    <?php foreach($tampil as $t):?>
    <tr>
      <th scope="row"><?php echo $t["id_kandidat"];?></th>
      <td><?php echo $t["fullname"];?></td>
      <td><img style="width: 50px;" src="../img/<?php echo $t["foto"];?>"> </td>
      <td><?php echo $t["visi"];?></td>
      <td><?php echo $t["misi"];?></td>
      <td><?php echo $t["suara"];?></td>
      <td>
        <button class="btn btn-warning" >
            <a class="text-decoration-none text-light" 
            href="mengubah.php?nisn=<?php echo $t["id_kandidat"]?>">
                ubah
            </a>
        </button>
        |
        <button class="btn btn-danger">
            <a class="text-decoration-none text-light" 
            href="menghapus.php?nisn=<?php echo $t["id_kandidat"]?>">
                hapus
            </a>
        </button>
      </td>
    </tr>
    <?php endforeach;?>
    
  </tbody>
</table>