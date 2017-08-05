<?php
/**
 * phpsnmp - a PHP SNMP library
 *
 * Copyright (C) 2004 David Eder <david@eder,us>
 *
 * Based on snmp - a Python SNMP library
 * Copyright (C) 2003 Unicity Pty Ltd <libsnmp@unicity.com.au>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @author David Eder <david@eder.us>
 * @copyright 2004 David Eder
 * @package phpSNMP
 * @version .7
 */

/**
 */
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1155.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1157.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1902.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1905.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc2104.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc3411.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc3412.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc3414.php');

define('SNMP_VERSION_1',  0);
define('SNMP_VERSION_2',  1);
define('SNMP_VERSION_2C', 1);
define('SNMP_VERSION_2U', 2); // doesn't work yet
define('SNMP_VERSION_3',  3); // doesn't work yet

/**
 * SNMP
 *
 * @package phpSNMP
 */
class snmp
{
  var $version = SNMP_VERSION_1;	// version can be SNMP_VERSION_1, SNMP_VERSION_2C, SNMP_VERSION_3
  var $timeout = 10.0;			// timeout in seconds for waiting for a return packet
  var $default_security;		// default security parameters

 /**
  * Constructor
  */
  public function __construct()
  {
    $this->default_security = array('community'=>'public', 'v3_max_size'=>65507, 'v3_flags'=>SNMP_AUTH_NOPRIV,
                                    'v3_security_model'=>SNMP_SECURITY_USM, 'v3_engine_id'=>'', 'v3_engine_boots'=>0,
                                    'v3_engine_time'=>0, 'v3_user'=>'', 'v3_auth'=>'', 'v3_priv'=>'',
                                    'v3_context_engine_id'=>'', 'v3_context_name'=>'', 'v3_hash'=>'md5',
                                    'v3_crypt_algorithm'=>'des', 'v3_crypt_mode'=>'cbc');
  }

 /**
  * get an oid from a single host
  *
  * @param string $host hostnames or ip addresses
  * @param mixed $target varbind array or oid (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $oid=>$value
  */
  public function get($host, $target, $security=NULL)
  {
    if(is_array($target))
      $varbind = $target;
    else
      $varbind = $this->build_varbind($target);

    $ret = $this->exec($host, 'get', $varbind, $security);

    return array_shift($ret);
  }

 /**
  * get an oid from multiple hosts
  *
  * @param array $hosts hostnames or ip addresses
  * @param mixed $target varbind array or oid (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $ip=>array($oid=>$value)
  */
  public function multi_get($hosts, $target, $security=NULL)
  {
    if(is_array($target))
      $varbind = $target;
    else
      $varbind = $this->build_varbind($target);
    return $this->exec($hosts, 'get', $varbind, $security);
  }

 /**
  * bulk get oids from a single host
  *
  * @param string $host hostname or ip address
  * @param array $oids (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $oid=>$value
  */
  public function bulk_get($host, $oids, $security=NULL)
  {
    $ret = $this->exec($host, 'getbulk', $this->build_varbind($oids), $security);

    return array_shift($ret);
  }

 /**
  * bulk get oids from a mulitple hosts
  *
  * @param string $hosts hostnames or ip addresses
  * @param array $oids (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $oid=>$value
  */
  public function multi_bulk_get($hosts, $oids, $security=NULL)
  {
    return $this->exec($hosts, 'getbulk', $this->build_varbind($oids), $security);
  }

 /**
  * walk an oid
  *
  * @param string $host hostnames or ip addresses
  * @param string $oid (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $ip=>array($oid=>$value)
  */
  public function walk($host, $oid, $security=NULL)
  {
    $ret = $this->exec($host, 'getnext', $this->build_varbind($oid), $security, $oid);

    return array_shift($ret);
  }

 /**
  * walk an oid on multiple hosts
  *
  * @param array $hosts hostnames or ip addresses
  * @param sring $oid (oids must be numeric)
  * @param array $security parameters
  * @return array in the format $ip=>array($oid=>$value)
  */
  public function multi_walk($hosts, $oid, $security=NULL)
  {
    return $this->exec($hosts, 'getnext', $this->build_varbind($oid), $security, $oid);
  }

 /**
  * set a variable
  *
  * @param string $host hostname or ip address
  * @param mixed $target varbind array or oid (oids must be numeric)
  * @param mixed $value to set
  * @param string $type 'i' = integer; 't' = time ticks; 'x' = hex string; 's' = string; 'a' = IP address; 'o' = object ID; 'n' = null value
  * @param array $security parameters
  */
  public function set($host, $target, $value=0, $type='i', $security=NULL)
  {
    if(is_array($target))
      $varbind = $target;
    else
      $varbind = $this->build_varbind($target, $value, $type);
    $this->exec($host, 'set', $varbind, $security);
  }

 /**
  * set a variable
  *
  * @param array $hosts hostnames or ip addresses
  * @param mixed $target varbind array or oid (oids must be numeric)
  * @param mixed $value to set
  * @param string $type 'i' = integer; 't' = time ticks; 'x' = hex string; 's' = string; 'a' = IP address; 'o' = object ID; 'n' = null value
  * @param array $security parameters
  */
  public function multi_set($hosts, $target, $value=0, $type='i', $security=NULL)
  {
    $this->set($hosts, $target, $value, $type, $security);
  }

 /**
  * send a trap
  *
  * @param string $manager hostname or ip address of the manager
  * @param array $security parameters
  * @param array $varbinds created by build_varbind
  * @param string $enterprise oid (oids must be numeric) of the object generating the trap (this is only for version 1)
  * @param string $agent hostname or ip address of the agent generating the trap (this is only for version 1)
  * @param integer $trap_type from TRAP_COLDSTART, TRAP_WARMSTART, TRAP_LINKDOWN, TRAP_LINKUP,
  *                                TRAP_AUTH_FAIL, TRAP_EGP_NEIGHBOR_LOSS, TRAP_ENTERPRISE_SPECIFIC
  *                                (this is only for version 1)
  * @param integer $specific_trap_type (this is only for version 1)
  * @param integer $timestamp time since last restart (this is only for version 1)
  */
  public function trap($manager, $security, $varbind, $enterprise='', $agent='', $trap_type=0, $specific_trap_type=0, $timestamp=0)
  {
    if(is_null($security))
      $security = $this->default_security;
    elseif(!is_array($security))
    {
      $s = $this->default_security;
      $s['community'] = $security;
      $security = $s;
    }

    if($this->version == SNMP_VERSION_1)
    {
      $pdu = new rfc1157_TrapPDU($enterprise, $agent, $trap_type, $specific_trap_type, $timestamp, $varbind);
      $msg = new rfc1157_Message(SNMP_VERSION_1, $security['community'], $pdu);
      $packet = $msg->encode();
    }
    elseif($this->version == SNMP_VERSION_2C || $this->version == SNMP_VERSION_3)
      $packet = $this->build_packet($varbind, $security, 'trap');
    else
    {
      trigger_error("Unknown SNMP version [{$this->version}]", E_USER_WARNING);
      return;
    }

    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    @socket_sendto($socket, $packet, strlen($packet), 0, $manager, 162);
  }

 /**
  * build a variable binding
  *
  * @param string $oid (oids must be numeric)
  * @param mixed $value to set
  * @param string $type 'i' = integer; 't' = time ticks; 'x' = hex string; 's' = string; 'a' = IP address; 'o' = object ID; 'n' = null value
  * @return array varbind
  */
  public function build_varbind($oid, $value=0, $type='n')
  {
    if(!is_array($oid)) $oid = array($oid);

    if(!is_array($value))
    {
      $val = $value;
      $value = array();
      foreach(array_keys($oid) as $i)
        $value[$i] = $val;
    }
    if(!is_array($type))
    {
      $t = $type;
      $type = array();
      foreach(array_keys($oid) as $i)
        $type[$i] = $t;
    }

    $varbind = array();
    foreach($oid as $i=>$o)
    {
      switch($type[$i])
      {
        case 'i': // integer
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_Integer($value[$i]));
          break;
        case 't': // time ticks
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_TimeTicks($value[$i]));
          break;
        case 'x': // hex string
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_OctetString(hexbin($value[$i])));
          break;
        case 's': // string
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_OctetString($value[$i]));
          break;
        case 'a': // ip address
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_IPAddress($value[$i]));
          break;
        case 'o': // object id
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_ObjectID($value[$i]));
          break;
        case 'n': // null value
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_Null());
          break;
        default:
          trigger_error("Unknown type $type", E_USER_WARNING);
          $varbind[] = new rfc1157_VarBind(new rfc1155_ObjectID($o), new rfc1155_Null());
      }
    }
    return $varbind;
  }

 /**
  * execute a poll on hosts
  *
  * @param mixed $target
  * @param string $community string
  * @param string $type is either get, getnext, or set
  * @param string $value to use for set
  * @param string $value_type to use for set
  * @return string packet
  */
  public function build_packet($varbind, $security=NULL, $type='get')
  {
    if(is_null($security))
      $security = $this->default_security;
    elseif(!is_array($security))
    {
      $s = $this->default_security;
      $s['community'] = $security;
      $security = $s;
    }

    if($this->version == SNMP_VERSION_1)
    {
      if($type == 'get')
        $pdu = new rfc1157_Get($this->assignRequestID(), 0, 0, $varbind);
      elseif($type == 'getnext')
        $pdu = new rfc1157_GetNext($this->assignRequestID(), 0, 0, $varbind);
      elseif($type == 'set')
        $pdu = new rfc1157_Set($this->assignRequestID(), 0, 0, $varbind);
      else
      {
        trigger_error("Unknown request type: $type", E_USER_WARNING);
        return '';
      }
      $msg = new rfc1157_Message(SNMP_VERSION_1, $security['community'], $pdu);
    }
    elseif($this->version == SNMP_VERSION_2C || $this->version == SNMP_VERSION_3)
    {
      $request_id = $this->assignRequestID();
      $reportable = SNMP_REPORTABLE;
      if($type == 'get')
        $pdu = new rfc1905_Get($request_id, 0, 0, $varbind);
      elseif($type == 'getnext')
        $pdu = new rfc1905_GetNext($request_id, 0, 0, $varbind);
      elseif($type == 'set')
        $pdu = new rfc1905_Set($request_id, 0, 0, $varbind);
      elseif($type == 'getbulk')
        $pdu = new rfc1905_GetBulk($request_id, count($varbind), 1, $varbind);
      elseif($type == 'inform')
        $pdu = new rfc1905_Inform($request_id, 0, 0, $varbind);
      elseif($type == 'trap')
      {
        $pdu = new rfc1905_Trap($request_id, 0, 0, $varbind);
        $reportable = 0;
      }
      elseif($type == 'report')
      {
        $pdu = new rfc1905_Report($request_id, 0, 0, $varbind);
        $reportable = 0;
      }
      else
      {
        trigger_error("Unknown request type: $type", E_USER_WARNING);
        return '';
      }
      if($this->version == SNMP_VERSION_2C)
        $msg = new rfc1905_Message(SNMP_VERSION_2C, $security['community'], $pdu);
      else
      {
        foreach($this->default_security as $key=>$value) if(!isset($security[$key])) $security[$key] = $value;

        $header = new rfc3412_Header($request_id, $security['v3_max_size'],
                                     $security['v3_flags'] | $reportable, $security['v3_security_model']);

        $usm = new rfc3414_USM($security['v3_engine_id'], $security['v3_engine_boots'],
                               $security['v3_engine_time'], $security['v3_user']);
        $usm->auth_password = $security['v3_auth'];
        $usm->priv_password = $security['v3_priv'];
        $usm->hash_function = $security['v3_hash'];
        $usm->crypt_algorithm = $security['v3_crypt_algorithm'];
        $usm->crypt_mode = $security['v3_crypt_mode'];

        $scopedpdu = new rfc3412_ScopedPDU($security['v3_context_engine_id'], $security['v3_context_name'], $pdu);
        $msg = new rfc3412_Message(SNMP_VERSION_3, $header, $usm, $scopedpdu);
      }
    }
    else
    {
      trigger_error("Unknown SNMP version {$this->version}", E_USER_WARNING);
      return '';
    }

    return $msg->encode();
  }

 /**
  * execute a poll on hosts
  *
  * @param array $hosts hostnames or ip addresses
  * @param string $type is either get, getnext, or set
  * @param string $packet to send
  * @param array $security parameters
  * @param string $stop
  * @return array in the format $ip=>array($oid=>$value)
  */
  public function exec($hosts, $type, $varbind, $security=NULL, $stop='')
  {
    $queue = array();
    $buffer = $port = NULL;
    $ret = array();

    foreach($this->default_security as $key=>$value) if(!isset($security[$key])) $security[$key] = $value;

    $packet = $this->build_packet($varbind, $security, $type);

    // add each host to the queue
    if(!is_array($hosts)) $hosts = array($hosts);
    foreach($hosts as $host)
    {
      $h = ip2long($host);
      if($h == -1 || $h === false) $host = gethostbyname($host); // we don't like hostnames
      $queue[] = array($packet, $host);
      $ret[$host] = array();
    }

    // create a message to decode with
    if($this->version == SNMP_VERSION_1)
      $msg = new rfc1157_Message();
    elseif($this->version == SNMP_VERSION_2C)
      $msg = new rfc1905_Message();
    elseif($this->version == SNMP_VERSION_3)
    {
      $usm = new rfc3414_USM();
      $usm->auth_password = $security['v3_auth'];
      $usm->priv_password = $security['v3_priv'];
      $usm->hash_function = $security['v3_hash'];
      $usm->crypt_algorithm = $security['v3_crypt_algorithm'];
      $usm->crypt_mode = $security['v3_crypt_mode'];
      $msg = new rfc3412_Message(SNMP_VERSION_3, new rfc3412_Header(), $usm);
    }
    else
    {
      trigger_error("Unknown SNMP version {$this->version}", E_USER_WARNING);
      return array();
    }

    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    if($socket === false)
    {
      trigger_error('Unable to create socket.', E_USER_WARNING);
      return array();
    }
    if(!socket_set_nonblock($socket))
      trigger_error('Unable to set socket to nonblocking.', E_USER_WARNING);

    $sent = 0;
    $received = 0;
    $t = $this->microtime();
    $block_state = 0; // 0 = nonblock, 1 = block, 2 = failed block
    while(count($queue))
    {
      do
      {
        if(count($queue))
        {
          // send next queue entry
          $entry = array_shift($queue);
          if(strlen($entry[0]))
          {
            if($block_state == 1)
            {
              socket_set_nonblock($socket);
              $block_state = 0;
            }

            if(@socket_sendto($socket, $entry[0], strlen($entry[0]), 0, $entry[1], 161) === false)
              trigger_error('Unable to send packet.', E_USER_WARNING);
            else
              $sent++;
            $t = $this->microtime();
          }
        }
        elseif($block_state == 0)
        {
          // we are done sending, try to set state to blocking I/O with a timeout
          if(@socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array('sec'=>floor($this->timeout), 'usec'=>0)))
          {
            socket_set_block($socket);
            $block_state = 1;
          }
          else
            $block_state = 2;
        }
        elseif($block_state == 2) // sleep if we failed to set a timeout
        {
          usleep(10000);
        }

        $buffer = $rhost = NULL;
        @socket_recvfrom($socket, $buffer, 4096, 0, $rhost, $port);
        if($buffer != '' && isset($ret[$rhost]))
        {
          $received++;

          $msg = $msg->decode($buffer);

          if($security['v3_context_engine_id'] == '' && $msg->version() == SNMP_VERSION_3)
          {
            $usm = $msg->usm_security();
            $security['v3_engine_id'] = $usm->engineID();
            $security['v3_engine_boots'] = $usm->engineBoots();
            $security['v3_engine_time'] = $usm->engineTime();

            $spdu = $msg->scopedPDU();
            $security['v3_context_engine_id'] = $spdu->engineID();
            $security['v3_context_name'] = $spdu->name();

            $queue[] = array($this->build_packet($varbind, $security, $type), $rhost);
          }
          else
          {
            $pdu = $msg->pdu();

            if($pdu->errorStatus()) trigger_error($pdu->errorString(), E_USER_WARNING);

            foreach($pdu->varBindList() as $val)
            {
              $oid = $val->value[0]->toString();
              if(($stop == '' || strpos(' '. $oid, $stop) != 0) && !isset($ret[$rhost][$oid]))
              {
                if($type == 'getnext')
                  $queue[] = array($this->build_packet($this->build_varbind($oid), $security, 'getnext'), $rhost);
                $ret[$rhost][$oid] = $val->value[1]->toString();
              }
            }
          }
        }
      } while($sent != $received && $this->microtime() - $t <= $this->timeout);
    }
    return $ret;
  }

 /**
  * Assign a unique requestID
  *
  * @return integer a request id
  */
  public function assignRequestID()
  {
    static $nextRequestID = 0;
    if($nextRequestID == 0 || $nextRequestID >= 2147483647) $nextRequestID = mt_rand();
    return $nextRequestID++;
  }

 /**
  * Get microtime as a float
  *
  * @return float microtime
  */
  public function microtime()
  {
    list($usec, $sec) = explode(' ', microtime());
    return ((float)$usec + (float)$sec);
  }
}
?>
