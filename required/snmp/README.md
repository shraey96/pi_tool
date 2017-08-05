#phpSNMP

phpSNMP is an SNMP implementation based on libsnmp, which is written in Python. It has been ported to 100% pure PHP.

**Why not just use the SNMP extension?**

The data return from the SNMP extension is not uniform accross platforms with different MIBs installed.
The SNMP extension does not support traps.
The SNMP extension does not support parallel gets.
The SNMP extension does not support bulk gets.
The SNMP extension results in semi-frequent core dumps on FreeBSD (I think it has something to do with threads).
The SNMP extension requires building yet another extension into PHP.

**Usage**
```
<?php
  ini_set('memory_limit', '256M');

  require('snmp.php');

  $oid = '.1.3.6.1.2.1.69.1.1.3';
  $oid = '.1.3.6.1.6.3.15.1.1.4.0';

  // test the oid_format function
  $z = oid_format($oid, OID_TEXT);
  $zz = oid_format($z, OID_NUMERIC);
  echo "$oid => $z => $zz\n";

  $ip = '172.16.0.116'; 		// ip address or hostname
  $ips = array($ip, '172.16.0.64');	// array of ip addresses or hostnames
  $community = 'public';		// community string
  $oid = '.1.3.6.1.2.1.1';		// only numerical oids are supported
  $oids = array('.1.3.6.1.2.1.1.1', '.1.3.6.1.2.1.1.3');

  $snmp = new snmp();

  $snmp->version = SNMP_VERSION_2;

  print_r($snmp->walk($ip, $oid, ['community' => $community]));
  print_r($snmp->multi_walk($ips, $oid, ['community' => $community]));


  $snmp->version = SNMP_VERSION_3;
  print_r($snmp->get('localhost', '.1.3.6.1.2.1.1.3.0', array('v3_flags'=>SNMP_AUTH_PRIV, 'v3_user'=>'v3user',
                                                              'v3_auth'=>'authpassword', 'v3_priv'=>'privpassword')));

  // get system uptime
  print_r($snmp->get($ip, '.1.3.6.1.2.1.1.3.0', ['community' => $community]));
  print_r($snmp->multi_get($ips, '.1.3.6.1.2.1.1.3.0', ['community' => $community]));

  // bulk get
  print_r($snmp->bulk_get($ip, $oids));

  // reset cable modem(s)
  $oid = '.1.3.6.1.3.83.1.1.4.0.1.1.3.0';
  $snmp->set($ip, $oid, 1, 'i', ['community' => 'private']);
  $snmp->multi_set($ips, $oid, 1, 'i', ['community' => 'private']);

  // send a trap
  $ip = '123.45.12.3';
  $community = 'public';
  $varbind = $snmp->build_varbind('.1.3.6.1.3.83.1.1.4.1', 17, 'i');
  $enterprise = '.1.3.6.1.3.83.1.1.4.0.1.1.3.0';
  $agent = '127.0.0.1';
  $trap_type = TRAP_LINKUP;
  $specific_trap_type = 2;
  $uptime = 123;

  $snmp->trap($ip, $community, $varbind, $enterprise, $agent, $trap_type, $specific_trap_type, $uptime);
?>
```
