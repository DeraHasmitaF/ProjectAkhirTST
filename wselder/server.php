<?php
 ini_set ("soap.wsdl_cache_enabled",0);
 header ("Access-Control-Allow-Origin:*");


require ('VoteAsses.php');
$server = new SoapServer ('VoteAsses.wsdl');
$server -> setClass ('VoteAsses');
$server-> handle();