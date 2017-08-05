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
 * @subpackage rfc1155
 * @version .7
 */

/**
 */

require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1155.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1905.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc3411.php');

define('SNMP_NOAUTH_NOPRIV', 0);
define('SNMP_AUTH_NOPRIV',   1);
define('SNMP_AUTH_PRIV',     3);
define('SNMP_REPORTABLE',    4);

define('SNMP_SECURITY_ANY',  0);
define('SNMP_SECURITY_V1',   1);
define('SNMP_SECURITY_V2C',  2);
define('SNMP_SECURITY_USM',  3);

/**
 * SNMP v3 Message
 *
 * @package phpSNMP
 * @subpackage rfc3412
 */
class rfc3412_Message extends rfc1155_Sequence
{
 /**
  * Constructor
  *
  * @param integer $version
  * @param rfc3412_Header $header
  * @param rfc3414_USM $security
  * @param rfc3412_ScopedPDU $scopedpdu
  */
  public function __construct($version=SNMP_VERSION_3, $header=NULL, $usm_security=NULL, $scopedpdu=NULL)
  {
    parent::__construct();

    if(is_null($header)) $header = new rfc3412_Header();
    if(is_null($usm_security)) $usm_security = new rfc3414_USM();
    if(is_null($scopedpdu)) $scopedpdu = new rfc3412_ScopedPDU();

    $this->value = array(new rfc1155_Integer($version), $header, $usm_security, $scopedpdu);
  }

 /**
  * Get/Set Version
  *
  * @param integer $value
  * @return integer
  */
  public function version($value=NULL)
  {
    if(!is_null($value)) $this->value[0] = new rfc1155_Integer($value);
    return $this->value[0]->value;
  }

 /**
  * Get/Set Header
  *
  * @param rfc3412_Header $value
  * @return rfc3412_Header
  */
  public function header($value=NULL)
  {
    if(!is_null($value)) $this->value[1] = $value;
    return $this->value[1];
  }

 /**
  * Get/Set USM Security
  *
  * @param rfc3414_USM $value
  * @return rfc3414_USM
  */
  public function usm_security($value=NULL)
  {
    if(!is_null($value)) $this->value[2] = $value;
    return $this->value[2];
  }

 /**
  * Get/Set Scoped PDU
  *
  * @param rfc3412_ScopedPDU $value
  * @return rfc3412_ScopedPDU
  */
  public function scopedPDU($value=NULL)
  {
    if(!is_null($value)) $this->value[3] = $value;
    return $this->value[3];
  }

 /**
  * Get/Set PDU
  *
  * @param rfc1905_PDU $value
  * @return rfc1905_PDU
  */
  public function pdu($value=NULL)
  {
    if(!is_null($value))
      $this->value[3]->pdu($value);
    return $this->value[3]->pdu();
  }

 /**
  * Decode Stream
  *
  * decode() an octet stream into a sequence of Asn1Objects
  *
  * @param string $stream
  * @return rfc3412_Message
  */
  public function decode($stream)
  {
    $usm = $this->usm_security();

    $this->value = parent::decode($stream);

    if(count($this->value) != 1)
      trigger_error('Malformed Message: More than one object decoded.', E_USER_WARNING);
    $this->value = $this->value[0]->value;
    if(count($this->value) != 4)
      trigger_error('Malformed Message: Incorrect sequence length ' . count($this->value), E_USER_WARNING);

    $header = $this->header();

    $header = $this->header(new rfc3412_Header($header->value[0]->value, $header->value[1]->value,
                                               ord($header->value[2]->value), $header->value[3]->value));

    $usm->decode($this->value[2]->value);
    $this->usm_security($usm);

    if($header->auth_flag())
    {
      // authenticate
      $usm = $this->usm_security();
      $auth = $usm->auth();
      $usm->auth(str_repeat(chr(0), USM_AUTH_KEY_LEN));
      $usms = new rfc1155_OctetString($usm->encode());
      $contents = $this->value[0]->encode() . $header->encode() . $usms->encode() . $this->value[3]->encode();
      $packet = $this->encodeIdentifier() . $this->encodeLength(strlen($contents)) . $contents;
      $hmac = substr(HMAC($packet, $usm->generate_key('auth'), $usm->hash_function), 0, USM_AUTH_KEY_LEN);
      if($hmac != $auth)
      {
        trigger_error('Message is not authentic!', E_USER_WARNING);
        $this->value[3] = new rfc3412_ScopedPDU();
        return $this;
      }

      if($header->priv_flag())
      {
        $clear = $usm->decrypt($this->value[3]->value);
        $spdu = new rfc3412_ScopedPDU();
        list($len, $c) = $spdu->decodeLength(substr($clear, 1));
        $len += strlen($clear) - strlen($c);
        $clear = substr($clear, 0, $len);
        $this->value[3] = $spdu->decode($clear);
      }
      else
        $this->value[3] = new rfc3412_ScopedPDU($this->value[3]->value[0]->value, $this->value[3]->value[1]->value, $this->value[3]->value[2]);
    }
    else
      $this->value[3] = new rfc3412_ScopedPDU($this->value[3]->value[0]->value, $this->value[3]->value[1]->value, $this->value[3]->value[2]);

    return $this;
  }

 /**
  * Encode Contents
  *
  * @return string
  */
  public function encodeContents()
  {
    $version = $this->value[0];
    $header = $this->header();
    $usm = $this->usm_security();
    $spdu = $this->scopedPDU();

    if($usm->engineID() == '')
    {
      $header->flags(SNMP_REPORTABLE);
      $usm = new rfc3414_USM();
      $pdu = $spdu->pdu();
      $pdu->varBindList(array());
      $spdu = new rfc3412_ScopedPDU('', '', $pdu);
    }

    $spdu = $spdu->encode();

    if($header->auth_flag())
    {
      if($header->priv_flag())
      {
        $spdu = new rfc1155_OctetString($usm->encrypt($spdu));
        $spdu = $spdu->encode();
      }

      $usm->auth(str_repeat(chr(0), USM_AUTH_KEY_LEN));
      $usms = new rfc1155_OctetString($usm->encode());
      $contents = $version->encode() . $header->encode() . $usms->encode() . $spdu;
      $packet = $this->encodeIdentifier() . $this->encodeLength(strlen($contents)) . $contents;
      $hmac = HMAC($packet, $usm->generate_key('auth'), $usm->hash_function);
      $usm->auth($hmac);
    }

    $usms = new rfc1155_OctetString($usm->encode());
    return $version->encode() . $header->encode() . $usms->encode() . $spdu;
  }
}

/**
 * SNMP v3 Message Header
 *
 * @package phpSNMP
 * @subpackage rfc3412
 */
class rfc3412_Header extends rfc1155_Sequence
{
 /**
  * Constructor
  *
  * @param integer $msgid
  * @param string $flags noAuthNoPriv(0), authNoPriv(1), authPriv(3)
  * @param string $security any(0), v1(1), v2c(2), usm(3)
  */
  public function __construct($msgid=0, $max_size=65507, $flags=SNMP_NOAUTH_NOPRIV, $security=SNMP_SECURITY_USM)
  {
    parent::__construct();
    $this->value = array(new rfc1155_Integer($msgid), new rfc1155_Integer($max_size),
                         new rfc1155_OctetString(chr($flags)), new rfc1155_Integer($security));
  }

 /**
  * to String
  *
  * @return string
  */
  public function toString()
  {
    $flags = array();
    $f = ord($this->value[2]->value);
    if($f & 1) $flags[] = 'AUTH';
    if($f & 2) $flags[] = 'PRIV';
    if($f & 4) $flags[] = 'REPORTABLE';
    $flags = join('|', $flags) . "($f)";

    switch($this->value[3]->value)
    {
      case SNMP_SECURITY_ANY: $security = 'ANY'; break;
      case SNMP_SECURITY_V1: $security = 'V1'; break;
      case SNMP_SECURITY_V2C: $security = 'V2C'; break;
      case SNMP_SECURITY_USM: $security = 'USM'; break;
      default: $this->value[3]->value;
    }

    return get_class($this) . "(MsgID:{$this->value[0]->value},max_size:{$this->value[1]->value},flags:$flags,security:$security)";
  }

 /**
  * Get/Set Message ID
  *
  * @param integer $value
  * @return integer
  */
  public function msgid($value=NULL)
  {
    if(!is_null($value)) $this->value[0]->value = $value;
    return $this->value[0]->value;
  }

 /**
  * Get/Set Max Message Size
  *
  * @param integer $value
  * @return integer
  */
  public function maxsize($value=NULL)
  {
    if(!is_null($value)) $this->value[1]->value = $value;
    return $this->value[1]->value;
  }

 /**
  * Get/Set Message Flags
  *
  * @param integer $value
  * @return integer
  */
  public function flags($value=NULL)
  {
    if(!is_null($value)) $this->value[2]->value = chr($value);
    return ord($this->value[2]->value);
  }

 /**
  * Get/Set Auth Flag
  *
  * @param boolean $value
  * @return boolean
  */
  public function auth_flag($value=NULL)
  {
    if(!is_null($value))
    {
      if($value)
        $this->value[2]->value |= chr(1); // set SNMP_AUTH;
      else
        $this->value[2]->value &= chr(254); // unset SNMP_AUTH
    }
    return (($this->value[2]->value & chr(1)) == chr(1)) ? true : false;
  }

 /**
  * Get/Set Priv Flag
  *
  * @param boolean $value
  * @return boolean
  */
  public function priv_flag($value=NULL)
  {
    if(!is_null($value))
    {
      if($value)
        $this->value[2]->value |= chr(3); // set SNMP_AUTH_PRIV;
      else
        $this->value[2]->value &= chr(253); // unset PRIV
    }
    return (($this->value[2]->value & chr(2)) == chr(2)) ? true : false;
  }

 /**
  * Get/Set Reportable Flag
  *
  * @param boolean $value
  * @return boolean
  */
  public function reportable_flag($value=NULL)
  {
    if(!is_null($value))
    {
      if($value)
        $this->value[2]->value |= chr(4); // set SNMP_REPORTABLE;
      else
        $this->value[2]->value &= chr(251); // unset SNMP_REPORTABLE
    }
    return ($this->value[2]->value & chr(4) == chr(4)) ? true : false;
  }

 /**
  * Get/Set Security Mode
  *
  * @param integer $value SNMP_SECURITY_ANY, SNMP_SECURITY_V1, SNMP_SECURITY_V2C, or SNMP_SECURITY_USM
  * @return integer
  */
  public function security($value=NULL)
  {
    if(!is_null($value)) $this->value[3]->value = $value;
    return $this->value[3]->value;
  }

 /**
  * Decode Stream
  *
  * decode() an octet stream into a sequence of Asn1Objects
  *
  * @param string $stream
  * @return rfc3412_Header
  */
  public function decode($stream)
  {
    parent::decode($stream);
    if(count($this->value) != 1)
      trigger_error('Malformed Message: More than one object decoded.', E_USER_WARNING);
    if(count($this->value[0]->value) != 4)
      trigger_error('Malformed Message: Incorrect sequence length ' . count($this->value[0]->value), E_USER_WARNING);
    return $this;
  }
}

/**
 * SNMP v3 Scoped PDU
 *
 * @package phpSNMP
 * @subpackage rfc3412
 */
class rfc3412_ScopedPDU extends rfc1155_Sequence
{
 /**
  * Constructor
  *
  * @param string $engineid
  * @param string $name
  * @param rfc1905_PDU $pdu
  */
  public function __construct($engineid='', $name='', $pdu=NULL)
  {
    parent::__construct();
    if(is_null($pdu)) $pdu = new rfc1905_PDU();
    $this->value = array(new rfc3411_EngineID($engineid), new rfc1155_OctetString($name), $pdu);
  }

 /**
  * Get/Set Context Engine ID
  *
  * @param string $value
  * @return string
  */
  public function engineID($value=NULL)
  {
    if(!is_null($value)) $this->value[0]->value = $value;
    return $this->value[0]->value;
  }

 /**
  * Get/Set Context Name
  *
  * @param string $value
  * @return string
  */
  public function name($value=NULL)
  {
    if(!is_null($value)) $this->value[1]->value = $value;
    return $this->value[1]->value;
  }

 /**
  * Get/Set PDU
  *
  * @param rfc1905_PDU $value
  * @return rfc1905_PDU
  */
  public function pdu($value=NULL)
  {
    if(!is_null($value)) $this->value[2] = $value;
    return $this->value[2];
  }

 /**
  * To String
  *
  * @return string
  */
  public function toString()
  {
    $eid = $this->value[0]->toString();
    $name = $this->value[1]->toString();
    $pdu = $this->pdu();
    $pdu = $pdu->toString();
    return get_class($this) . "(engineID:$eid,Name:$name,pdu:$pdu)";
  }

 /**
  * Decode Stream
  *
  * decode() an octet stream into a sequence of Asn1Objects
  *
  * @param string $stream
  * @return rfc3412_ScopedPDU
  */
  public function decode($stream)
  {
    $this->value = parent::decode($stream);
    if(count($this->value) != 1)
      trigger_error('Malformed Message: More than one object decoded.', E_USER_WARNING);
    $this->value = $this->value[0]->value;
    if(count($this->value) != 3)
      trigger_error('Malformed Message: Incorrect sequence length ' . count($this->value), E_USER_WARNING);

    $this->value[0] = new rfc3411_EngineID($this->value[0]->value);

    return $this;
  }
}
?>
