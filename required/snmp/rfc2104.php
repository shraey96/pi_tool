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
 * @subpackage rfc2104
 * @version .7
 */

/**
 */

 /**
  * generate HMAC
  *
  * @param string $data
  * @param string $key
  * @param string $hash_function
  * @param integer $block_size
  * @return string
  */
  function HMAC($data, $key, $hash_function='md5', $block_size=64)
  {
    if(!is_callable($hash_function))
    {
      trigger_error("$hash_function does not exist.", E_USER_WARNING);
      return '';
    }

    if(strlen($key) > $block_size) $key = pack('H*', $hash_function($key));

    $key = str_pad($key, $block_size, chr(0));

    $ipad = $key ^ str_repeat(chr(0x36), $block_size);
    $opad = $key ^ str_repeat(chr(0x5c), $block_size);

    $digest = pack('H*', $hash_function($ipad . $data));

    return pack('H*', $hash_function($opad . $digest));
  }

?>
