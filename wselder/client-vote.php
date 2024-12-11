<?php

$wsdl = "http://localhost/wselder/VoteAsses.wsdl";
$client = new SoapClient($wsdl);
    $tugasLMS = true; 
    $vote = $client->getVote($tugasLMS);

    header('Content-Type: application/json');
    echo json_encode($vote);
