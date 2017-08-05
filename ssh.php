
<?php

///Include files for SSH2 (phpsshlib) library and SNMP library 
include('required/vendor/autoload.php');
include('required/snmp/snmp.php');





/////Set session variables////
  

    session_start();

      $ip = $_SESSION['ip'];
      $uname = $_SESSION['uname'];
      $pass = $_SESSION['pass'];
      $comm = $_SESSION['comm'];

  session_write_close();


//$ansi = new ANSI();
$snmp = new snmp();
$snmp->version = SNMP_VERSION_2;



///needed_stuff array will be sent javascript(script1.js) with data we need
$needed_stuff = array();






/// recieve function name from JS file
$functionexe = $_POST['functionexe'];





//// Establish ssh connection to currently set IP, usernam, password and community_name  session
function connect()
    {
   global $ssh, $ip, $uname, $pass;
    $ssh = new \phpseclib\Net\SSH2($ip);
        
    if (!$ssh->login($uname, $pass )) {
        exit('Login Failed');
        
    }

}






///SNMP////
///Check if system is up/online by sending SNMP request for current time.
if($functionexe=="sysUp")
{
$cmd =($snmp->walk($ip, '1.3.6.1.2.1.1.3',['community' => $comm]));
if(sizeof($cmd)>0)
    echo json_encode(0);
else
    echo json_encode(1);

}


////Run SNMP commands to fetch free, used, available, swap etc RAM
elseif($functionexe=="showRAM")
{
    
$tswap =($snmp->get($ip, '.1.3.6.1.4.1.2021.4.3.0',['community' => $comm]));
$tswap = implode(',' , $tswap);
$tswap = explode(',' , $tswap);
    
$needed_stuff["tswap"] =  $tswap[0]/1000000;
    
$aswap =($snmp->get($ip, '1.3.6.1.4.1.2021.4.4.0',['community' => $comm]));
$aswap = implode(',' , $aswap);
$aswap = explode(',' , $aswap);
    
$needed_stuff["aswap"] =  $aswap[0]/1000000;    
$needed_stuff["fswap"] =  (($tswap[0] - $aswap[0])/1000000);    


//total
$tram =($snmp->get($ip, '.1.3.6.1.4.1.2021.4.5.0',['community' => $comm]));
$tram = implode(',' , $tram);
$tram = explode(',' , $tram);
$needed_stuff["tram"] =  $tram[0]/1000000;  

    
//free
$fram =($snmp->get($ip, '.1.3.6.1.4.1.2021.4.11.0',['community' => $comm]));
$fram = implode(',' , $fram);
$fram = explode(',' , $fram);
$needed_stuff["fram"] =  $fram[0]/1000000;  
    
    //used
$needed_stuff["uram"] =  ($tram[0]/1000000 -  $fram[0]/1000000);  
  
    //buffered
$buff =($snmp->get($ip, '.1.3.6.1.4.1.2021.4.14.0',['community' => $comm]));
$buff = implode(',' , $buff);
$buff = explode(',' , $buff);
    $needed_stuff["buff"] =  $buff[0]/1000000;

    //cached
$cach =($snmp->get($ip, '.1.3.6.1.4.1.2021.4.15.0',['community' => $comm]));
$cach = implode(',' , $cach);
$cach = explode(',' , $cach);
    $needed_stuff["cach"] =  $cach[0]/1000000;

////push all to needed_array and echo is back to JS file
echo json_encode($needed_stuff);

    
}


////show list of interfaces on the device along with their status and bandwidth
elseif($functionexe=="showNet")
{ $ip_add = array();
  $interface_diff = array();
   
    /// List interfaces and push to needed_stuff array
$netint =($snmp->walk($ip, '1.3.6.1.2.1.2.2.1.2',['community' => $comm]));
$netint = implode(',' , $netint);
$netint = explode(',' , $netint);
for($i=0; $i<sizeof($netint); $i++)
{array_push($needed_stuff, $netint[$i]);
array_push($interface_diff, $i); }
    
    
    
    ///get IP address of interfaces and push to needed_stuff array
$intip =($snmp->walk($ip, '.1.3.6.1.2.1.4.20.1.2',['community' => $comm]));
    

 
 /// for interfaces without IP, get their index and push N/A to array
$xindex = implode(',' , $intip);
$xindex = explode(',' , $xindex);

for($i=0;$i<sizeof($xindex);$i++)
{
$xindex[$i] = $xindex[$i] - 1;    
}

$interface_diff = array_keys(array_diff($interface_diff,$xindex)); //get null indexes


//print_r(array_keys($interface_diff)); // returns array containing keys    
    
$intip = array_keys($intip);
$intip = str_replace(".1.3.6.1.2.1.4.20.1.2.", "", $intip);
$intip = implode(',', $intip);
$intip = explode(',', $intip);
for($i=0; $i<sizeof($intip); $i++)
{array_push($ip_add, $intip[$i]);}

 /// for interfaces without IP, get their index and push N/A to array
  
 for($i=0; $i<sizeof($interface_diff);$i++)
{array_splice($ip_add, $interface_diff[$i], 0, "n/a");}


$needed_stuff = (array_merge($needed_stuff,$ip_add)); ///combine both arrays
    
 
/// get up/down stats for each interface and   push to needed_stuff array 
$intstat =($snmp->walk($ip, '.1.3.6.1.2.1.2.2.1.8',['community' => $comm]));
$intstat = implode(',' , $intstat);
$intstat =explode(',' , $intstat);
for($i=0; $i<sizeof($intstat); $i++)
{   if($intstat[$i]=="1")
    {array_push($needed_stuff, "Interface Up");}
    else
    {array_push($needed_stuff, "Interface Down");}            
}
  
////calculate the following for interfaces:
    //inoctets
$cmd =($snmp->walk($ip, '.1.3.6.1.2.1.2.2.1.10',['community' => $comm]));
$cmd = implode(',' , $cmd);
$cmd =explode(',' , $cmd);
//outoctets
$cmd1 =($snmp->walk($ip, '.1.3.6.1.2.1.2.2.1.16',['community' => $comm]));
$cmd1 = implode(',' , $cmd1);
$cmd1 =explode(',' , $cmd1);

 
///put 2 second sleep for script and recalculate above things
sleep(2);
 
//inoctets
$cmd2 =($snmp->walk($ip, '.1.3.6.1.2.1.2.2.1.10',['community' => $comm]));
$cmd2 = implode(',' , $cmd2);
$cmd2 = explode(',' , $cmd2);
//outoctets
$cmd3 =($snmp->walk($ip, '.1.3.6.1.2.1.2.2.1.16',['community' => $comm]));

$cmd3 = implode(',' , $cmd3);
$cmd3 = explode(',' , $cmd3);

 ///  push to needed_stuff array the received bytes
for($i=0; $i<sizeof($cmd);$i++)
{
    array_push($needed_stuff, ((($cmd2[$i] - $cmd[$i])*8)/2)); //rx
}
    
  ////   push to needed_stuff array the transmitted bytes  
for($i=0; $i<sizeof($cmd);$i++)
{
    array_push($needed_stuff, ((($cmd3[$i] - $cmd1[$i])*8)/2)); //tx
}
    
echo json_encode($needed_stuff);
  
}


///Get CPU usage for each core using SNMP and   push to needed_stuff array

elseif($functionexe=="showCPU")
{
    $cpu =($snmp->walk($ip, '.1.3.6.1.2.1.25.3.3.1.2',['community' => $comm]));
    $cpu = implode(',' , $cpu);
    $cpu =explode(',' , $cpu);
    echo json_encode($cpu);
}



//Use SSH to get status particular services
elseif($functionexe=="showService")
{ 
      $service_for_all = array("mysql", "ssh", "ntp", "snmpd", "apache2", "bluetooth", "networking", "cron");
  
    connect();
     

for($i=0; $i<sizeof($service_for_all);$i++)
{  
    ///if (running) keyword is there in output, service is running
   // array_push($needed_stuff, $service_for_all[$i]);
    
    $cmd = $ssh->exec("/etc/init.d/$service_for_all[$i] status");
    $cmd = (preg_split('/\s+/', trim($cmd)));

  if (array_search("(running)", $cmd) ||  array_search("(exited)", $cmd))
 { //array_push($needed_stuff, "running...");
 $var = "running...";
      // $needed_stuff[$service_for_all[$i]] =  "running..."; 
  
  }
    else
 {//array_push($needed_stuff, "stopped.");
 $var = "stopped";
        //$needed_stuff[$service_for_all[$i]] =  "stopped"; 
 }

        $needed_stuffx["service"] = $service_for_all[$i];
        $needed_stuffx["status"] = $var;
 array_push($needed_stuff,$needed_stuffx);
}
    
    echo json_encode($needed_stuff);  
}

//Using SSH check disk usage
elseif($functionexe=="showDisk")
{
    connect();
    
$disk = $ssh->exec("df -h");
$disk = (preg_split('/\s+/', trim($disk)));
    ///start grabbing data from 7th index (gives filesystem, free space, available space etc of disks)
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
echo json_encode($needed_stuff);    
}


///get active connection ports using SSH

/*
elseif($functionexe=="showActPorts")
{
    connect();
    
    $actports = $ssh->exec("netstat -antlp");
    $actports = (preg_split('/\s+/', trim($actports)));
    for($i=22; $i<(sizeof($actports)); $i=$i+7)  
    {
        array_push($needed_stuff, $actports[$i]);
        array_push($needed_stuff, $actports[$i - 3]);
    } 
     echo json_encode($needed_stuff);
}

*/


elseif($functionexe=="MYSQLErrorLogs")
{
    connect();
    
    if(isset($_POST['control']))
   {    $control = $_POST['control'];
        $lines = $_POST['lines'];
        $logs = $ssh->exec("$control -$lines /var/log/mysql/error.log");
   }
    else
    {
       $logs = $ssh->exec("tail -1000 /var/log/mysql/error.log"); 
    }
    
    
    $logs = (preg_split("/(\r\n|\n|\r)/", trim($logs))); //split using line break
    
     echo json_encode($logs);
}



elseif($functionexe=="MYSQLLogs")
{
    connect();
    
        if(isset($_POST['control']))
   {    $control = $_POST['control'];
        $lines = $_POST['lines'];
        $logs = $ssh->exec("$control -$lines /var/log/mysql.log");
   }
    else
    {
        $logs = $ssh->exec("tail -1000 /var/log/mysql.log"); 
    }
    
    $logs = (preg_split("/(\r\n|\n|\r)/", trim($logs))); //split using line break
    
     echo json_encode($logs);
}
elseif($functionexe=="SysLogs")
{
    connect();
    
        if(isset($_POST['control']))
   {    $control = $_POST['control'];
        $lines = $_POST['lines'];
        $logs = $ssh->exec("$control -$lines /var/log/syslog");
   }
    else
    {
      $logs = $ssh->exec("tail -1000 /var/log/syslog"); 
    }
    
    
    $logs = (preg_split("/(\r\n|\n|\r)/", trim($logs))); //split using line break
    
     echo json_encode($logs);
}

elseif($functionexe=="ApacheAccessLogs")
{
    connect();
    
        if(isset($_POST['control']))
   {    $control = $_POST['control'];
        $lines = $_POST['lines'];
        $logs = $ssh->exec("$control -$lines /var/log/apache2/access.log");
   }
    else
    {
      $logs = $ssh->exec("tail -1000 /var/log/apache2/access.log"); 
    }
    
    $logs = (preg_split("/(\r\n|\n|\r)/", trim($logs))); //split using line break
    
     echo json_encode($logs);
}
elseif($functionexe=="ApacheErrorLogs")
{   
    connect(); 
    
        if(isset($_POST['control']))
   {    $control = $_POST['control'];
        $lines = $_POST['lines'];
        $logs = $ssh->exec("$control -$lines /var/log/apache2/error.log");
   }
    else
    {
      $logs = $ssh->exec("tail -1000 /var/log/apache2/error.log");
    }
    
    
    $logs = (preg_split("/(\r\n|\n|\r)/", trim($logs))); //split using line break
    
     echo json_encode($logs);
}


//// Run SSH to show all running processes
elseif($functionexe=="showProc")
{
    connect();
$cmd = $ssh->exec("ps aux k-pid | head -15 | awk '{print $2 \" \" $3 \" \" $11}'");
$cmd = (preg_split('/\s+/', trim($cmd)));; //split using line break
  for($i=3; $i<(sizeof($cmd))-2; $i++)
    { 
        $needed_stuffx["pid"] = $cmd[$i];
        $needed_stuffx["cpu"] = $cmd[$i+1];
        $needed_stuffx["cmd"] = $cmd[$i+2];
        
       array_push($needed_stuff,$needed_stuffx);
    }
    echo json_encode($needed_stuff);
}

//// Kill process using SSH
elseif($functionexe=="killProc")
{   $control = $_POST['control'];
    connect();
    $cmd = $ssh->exec("pkill $control"); // processID for kill button
    echo json_encode($cmd);
}




////Start,Stop,Restart selected service using SSH
else
{   $control = $_POST['control'];
    connect();
    $cmd = $ssh->exec("service $functionexe  $control");
    echo json_encode($cmd);
}



?>