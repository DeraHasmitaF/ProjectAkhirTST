<?php

require "vendor/autoload.php";
require "VoteAsses.php";

$gen= new \PHP2WSDL\PHPClass2WSDL("VoteAsses", "http://localhost/wselder/server.php");

$gen -> generateWSDL();
file_put_contents ("VoteAsses.wsdl", $gen->dump());
echo "Done!";