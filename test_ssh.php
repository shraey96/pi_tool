<?php

include('required/vendor/autoload.php');
include('required/snmp/snmp.php');





/////Set session variables////
  $needed_stuff = array();

$ip = '192.168.43.11';
$uname = 'pi';
$pass = 'root123';




$snmp = new snmp();
$snmp->version = SNMP_VERSION_2;
$comm = "public";

$errors = array();

    /*
    
          $needed_stuffx["filesystem"] = $disk[$i];
        $needed_stuffx["size"] = $disk[$i+1];
        $needed_stuffx["used"] = $disk[$i+2];
        $needed_stuffx["avail"] = $disk[$i+3];
        $needed_stuffx["usep"] = $disk[$i+4];
       array_push($needed_stuff,$needed_stuffx);
    
    
    */
    
    
$ssh = new \phpseclib\Net\SSH2($ip);
        
    if (!$ssh->login($uname, $pass )) {
      // echo "errors";
      array_push($errors, "snmp connection failed"); 
       // echo json_encode($errors);
       //exit('Login Failed');
    }

$cmd =($snmp->walk($ip, '.1.3.6.1.2.1.1.3',['community' => $comm]));
if(sizeof($cmd)==0)
{   array_push($errors, "snmp connection failed"); }
echo json_encode($errors);
    
 /// for interfaces without IP, get their index and push N/A to array
  
 


    

//echo json_encode($needed_stuff);
  

//echo json_encode($cmd);
   /*
    for($i=7; $i<sizeof($disk); $i=$i+6)
    {       // array_push($needed_stuff, $disk[$i]);
        //array_push($needed_stuff, $disk[$i+1]);
       // array_push($needed_stuff, $disk[$i+2]);
      //  array_push($needed_stuff, $disk[$i+3]);
        
        $needed_stuffx["filesystem"] = $disk[$i];
        $needed_stuffx["size"] = $disk[$i+1];
        $needed_stuffx["used"] = $disk[$i+2];
        $needed_stuffx["avail"] = $disk[$i+3];
        $needed_stuffx["usep"] = $disk[$i+4];
       array_push($needed_stuff,$needed_stuffx);
    }
    */


 //  echo json_encode($needed_stuff);

/*
    for($i=11; $i<(sizeof($disk)); $i=$i+6)
    {
        array_push($needed_stuff, $disk[$i]);
    }

*/
//echo json_encode($needed_stuff);    
   
//$needed_stuff['networking'] =  "stopped"; 




/*
$ip = '192.168.43.111';
$comm = 'public';

$snmp = new snmp();
$snmp->version = SNMP_VERSION_2;

$tswap =($snmp->walk($ip, '1.3.6.1.6.3.10.2.1.3',['community' => $comm]));
print_r($tswap);
$tswap = implode(',' , $tswap);
$tswap = explode(',' , $tswap);
echo sizeof($tswap);
echo json_encode($tswap);

*/
?>