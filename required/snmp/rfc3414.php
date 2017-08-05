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
 * @subpackage rfc3414
 * @version .7
 */

/**
 */

require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1155.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc3411.php');

define('USM_AUTH_KEY_LEN', 12);
define('USM_SALT_LEN', 8);

/**
 * User-based Security Model (USM)
 *
 * @package phpSNMP
 * @subpackage rfc3414
 */
class rfc3414_USM extends rfc1155_Sequence
{
  var $auth_password = '';
  var $priv_password = '';
  var $hash_function = 'md5';
  var $crypt_algorithm = 'des';
  var $crypt_mode = 'cbc';

 /**
  * Constructor
  *
  * @param string $engine_id
  * @param integer $engine_boots
  * @param integer $engine_time
  * @param string $user
  * @param string $auth MD5 or SHA hash sum
  * @param string $priv DES salt
  */
  public function __construct($engine_id='', $engine_boots=0, $engine_time=0, $user='', $auth='', $priv='')
  {
    parent::__construct();
    if(strlen($user) > 32)
      trigger_error('user must be at most 32 characters', E_USER_WARNING);
    $this->value = array(new rfc3411_EngineID($engine_id), new rfc1155_Integer($engine_boots),
                         new rfc1155_Integer($engine_time), new rfc1155_OctetString($user),
                         new rfc1155_OctetString($auth), new rfc1155_OctetString($priv));
  }

 /**
  * Get/Set engine ID
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
  * Get/Set engine boots
  *
  * @param integer $value
  * @return integer
  */
  public function engineBoots($value=NULL)
  {
    if(!is_null($value)) $this->value[1]->value = $value;
    return $this->value[1]->value;
  }

 /**
  * Get/Set engine time
  *
  * @param integer $value
  * @return integer
  */
  public function engineTime($value=NULL)
  {
    if(!is_null($value)) $this->value[2]->value = $value;
    return $this->value[2]->value;
  }

 /**
  * Get/Set usm user
  *
  * @param string $value
  * @return string
  */
  public function user($value=NULL)
  {
    if(!is_null($value)) $this->value[3]->value = $value;
    return $this->value[3]->value;
  }

 /**
  * Get/Set auth parameters
  *
  * @param string $value
  * @return string
  */
  public function auth($value=NULL)
  {
    if(!is_null($value)) $this->value[4]->value = substr($value, 0, USM_AUTH_KEY_LEN);
    return $this->value[4]->value;
  }

 /**
  * Get/Set priv parameters
  *
  * @param string $value - a value of 'salt' generates a new priv parameter
  * @return string
  */
  public function priv($value=NULL)
  {
    static $salt = NULL;

    if(!is_null($value))
    {
      if($value == 'salt')
      {
        if(is_null($salt)) for($i = 0; $i < USM_SALT_LEN; $i++) $salt .= chr(rand(0, 255));

        $i = USM_SALT_LEN - 1;
        while($i)
        {
          if($salt{$i} == chr(255))
          {
            $salt{$i} = chr(0);
            $i--;
          }
          else
          {
            $salt{$i} = chr(ord($salt{$i}) + 1);
            $i = 0;
          }
        }
        $this->value[5]->value = $salt;
      }
      else
        $this->value[5]->value = $value;
    }
    return $this->value[5]->value;
  }

 /**
  * Decode Stream
  *
  * decode() an octet stream into a sequence of Asn1Objects
  *
  * @param string $stream
  * @return rfc3411_USM
  */
  public function decode($stream)
  {
    $this->value = parent::decode($stream);
    if(count($this->value) != 1)
      trigger_error('Malformed Message: More than one object decoded.', E_USER_WARNING);
    $this->value = $this->value[0]->value;
    if(count($this->value) != 6)
      trigger_error('Malformed Message: Incorrect sequence length ' . count($this->value), E_USER_WARNING);
    return $this;
  }

 /**
  * Generate a key
  *
  * @param string $password - 'auth' for auth_password, 'priv' for priv_password, anything else will be treated as a password
  * @return string key
  */
  public function generate_key($password)
  {
    if($password == 'auth')
      $password = $this->auth_password;
    elseif($password == 'priv')
      $password = $this->priv_password;

    $hashfn = $this->hash_function;
    $key = substr(str_repeat($password, ceil(1048576 / strlen($password))), 0, 1048576);
    $key = pack('H*', $hashfn($key));
    return pack('H*', $hashfn($key . $this->engineID() . $key));
  }

 /**
  * Generate initialization vector for DES
  *
  * @param string $key
  * @return string iv
  */
  public function generate_iv($key=NULL)
  {
    if(is_null($key)) $key = $this->generate_key('priv');
    $salt = $this->priv();
    return substr($key, strlen($key) - strlen($salt)) ^ $salt;
  }

 /**
  * Encrypt using crypt_algorithm and crypt_mode
  *
  * @param string $data
  * @return string
  */
  public function encrypt($data)
  {
    if(!(function_exists('mcrypt_module_open') && function_exists('mcrypt_generic')))
    {
      trigger_error('Mcrypt must be installed', E_USER_WARNING);
      return $data;
    }
    $key = $this->generate_key('priv');
    $this->priv('salt');
    $iv = $this->generate_iv($key);
    $td = mcrypt_module_open($this->crypt_algorithm, '', $this->crypt_mode, '');
    $ks = mcrypt_enc_get_key_size($td);
    $key = substr($key, 0, $ks);
    mcrypt_generic_init($td, $key, $iv);
    $ret = mcrypt_generic($td, $data);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return $ret;
  }

 /**
  * Decrypt using crypt_algorithm and crypt_mode
  *
  * @param string $data
  * @return string
  */
  public function decrypt($data)
  {
    if(!(function_exists('mcrypt_module_open') && function_exists('mdecrypt_generic')))
    {
      trigger_error('Mcrypt must be installed', E_USER_WARNING);
      return $data;
    }
    $key = $this->generate_key('priv');
    $iv = $this->generate_iv($key);
    $td = mcrypt_module_open($this->crypt_algorithm, '', $this->crypt_mode, '');
    $ks = mcrypt_enc_get_key_size($td);
    $key = substr($key, 0, $ks);
    mcrypt_generic_init($td, $key, $iv);
    $ret = mdecrypt_generic($td, $data);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return $ret;
  }
}
?>
