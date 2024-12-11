<?php
$conn=mysqli_connect("localhost:3307","root","","vote1");
function login($nisn){
    global $conn;
    $query = "SELECT*FROM siswa WHERE nisn=$nisn";
    $login = mysqli_query($conn,$query);
    $rows = [];
    while($data=mysqli_fetch_assoc($login)){
        $rows[]=$data;

    }
    return $rows;
}

function tampil($query){
    global $conn;
    $tampil = mysqli_query($conn,$query);
    $row = [];
    while($data=mysqli_fetch_assoc($tampil)){
        $rows[]=$data;
        
    }
    return $rows;
}

function tambah($data){
    global $conn;
    $nisn = $data["nisn"];
    $fullname = $data["fullname"];
    $kelas = $data["kelas"];
    $token = $data["token"];
    $status = $data["status"];
    $query = "INSERT INTO siswa VALUES 
    ('$nisn', '$fullname', '$kelas', '$token', '$status','0')";
    mysqli_query($conn,$query);
    return mysqli_affected_rows($conn);
}

function ubah($data,$nisn){
    global $conn;
    $nisn = $data["nisn"];
    $fullname = $data["fullname"];
    $kelas = $data["kelas"];
    $token = $data["token"];
    $status = $data["status"];
    $query = "UPDATE siswa SET 
    nisn='$nisn', fullname='$fullname', 
    kelas='$kelas', token='$token', status='$status'
    WHERE nisn=$nisn 
    ";
    mysqli_query($conn,$query);
    return mysqli_affected_rows($conn);
}

function hapus($nisn){
    global $conn;
    $query = "DELETE FROM siswa WHERE nisn=$nisn";
    $hapus = mysqli_query($conn, $query);
    return mysqli_affected_rows($conn);
}

function vote($nisn,$data){
    global $conn;
    $suara_sementara = $data["submit"];
    $suara = (int)$suara_sementara;
    var_dump($suara);
    $status = "sudah voting";
    $query = "UPDATE siswa SET status='$status', suara=$suara WHERE nisn=$nisn";
    mysqli_query($conn, $query);
    $hasil = mysqli_affected_rows($conn);
    var_dump($hasil);
    return $hasil;
}
function v_tampil($query){
    global $conn;
    $tampil = mysqli_query($conn,$query);
    $row = [];
    while($data=mysqli_fetch_assoc($tampil)){
        $rows[]=$data;
        
    }
    return $rows;
}

function v_tambah($data){
    global $conn;
    $id = $data["id_kandidat"];
    $fullname = $data["fullname"];
    $foto = $data["foto"];
    $visi = $data["visi"];
    $misi = $data["misi"];
    $suara = $data["suara"];
    $query = "INSERT INTO kandidat VALUES 
    ('$id', '$fullname', '$foto', '$visi', '$misi', '$suara')";
    mysqli_query($conn,$query);
    return mysqli_affected_rows($conn);
}

function v_ubah($data,$id){
    global $conn;
    $id = $data["id_kandidat"];
    $fullname = $data["fullname"];
    $foto = $data["foto"];
    $visi = $data["visi"];
    $misi = $data["misi"];
    $suara = $data["suara"];
    $query = "UPDATE kandidat SET 
    id_kandidat='$id', fullname='$fullname', 
    foto='$foto', visi='$visi', misi='$misi', suara='$suara'
    WHERE id_kandidat=$id 
    ";
    mysqli_query($conn,$query);
    return mysqli_affected_rows($conn);
}

function v_hapus($id){
    global $conn;
    $query = "DELETE FROM kandidat WHERE id_kandidat=$id";
    $hapus = mysqli_query($conn, $query);
    return mysqli_affected_rows($conn);
}
function a_login($query){
    global $conn;
    $newlogin = mysqli_query($conn,$query);
    $data=mysqli_fetch_assoc($newlogin);
    // $rows = [];
    // while($data=mysqli_fetch_assoc($newlogin)){
    //     $rows[]=$data;
    // }
    return $data;
}
?>