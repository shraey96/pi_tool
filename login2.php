<?php

include('required/vendor/autoload.php');
include('required/snmp/snmp.php');

$snmp = new snmp();
$snmp->version = SNMP_VERSION_2;



///needed_stuff array will be sent javascript(script1.js) with data we need
$errors = array();



  $uname = $_POST['uname'];
  $pass = $_POST['pass'];
  $ip = $_POST['ip'];
  $comm = $_POST['comm'];



$ssh = new \phpseclib\Net\SSH2($ip);
        
    if (!$ssh->login($uname, $pass )) {
       
        array_push($errors, "ssh login failed");
        echo json_encode($errors);
       //exit('Login Failed');
    }

$cmd =($snmp->walk($ip, '.1.3.6.1.2.1.1.3',['community' => $comm]));
if(sizeof($cmd)==0)
{   array_push($errors, "snmp connection failed"); }


if(sizeof($errors)==0)
{
     session_start();
     $_SESSION['ip'] = $ip;
     $_SESSION['uname'] = $uname;
     $_SESSION['pass'] = $pass;
     $_SESSION['comm'] = $comm;
}


echo json_encode($errors);




/*
$ip = '192.168.43.111';
$uname = 'pi';
$pass = 'root123';

    $ssh = new \phpseclib\Net\SSH2($ip);
        
    if (!$ssh->login($uname, $pass )) {
        exit('Login Failed');
        
    }


$cmd = $ssh->exec("ls");
    $cmd = (preg_split('/\s+/', trim($cmd)));
    echo json_encode($cmd);
*/

?>