<?php
include('required/vendor/autoload.php');
include('required/snmp/snmp.php');


    $functionN = $_POST['functionN'];
   
    $needed_stuff = array();


////Set IP session by verifying the password from DB

///Get current session IP and echo to JS FILE
if($functionN=="getIP")
{
    session_start();
    if(isset($_SESSION['ip']))
    {$needed_stuff['ip'] = $_SESSION['ip']; };
    
     
$snmp = new snmp();
$snmp->version = SNMP_VERSION_2;

$cmd =($snmp->get($_SESSION['ip'], '.1.3.6.1.2.1.1.5.0',['community' => $_SESSION['comm']]));
$cmd = implode(',' , $cmd);
$cmd = explode(',' , $cmd);
$needed_stuff['host'] = $cmd;     
   echo json_encode($needed_stuff);
    
  

}



    ?>