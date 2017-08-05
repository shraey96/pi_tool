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
 * @subpackage mib_compiler
 * @version .7
 */

/**
 */

  define('OID_NUMERIC', 1);
  define('OID_TEXT', 0);
  function oid_format($oid, $format=OID_TEXT)
  {
    static $nodes = NULL;

    if(is_null($oid) || (is_array($oid) && count($oid) == 0) || (!is_array($oid) && strlen($oid) == 0)) return $oid;

    if(is_null($nodes))
      $nodes = unserialize(file_get_contents(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'oid_format.data'));

    $ret_type = 'string';
    if(is_array($oid))
    {
      $oid = join('.', $oid);
      $ret_type = 'array';
    }
    elseif($oid{0} != '.')
      $oid = '1.3.6.1.2.1.' . $oid;

    while($oid{0} == '.') $oid = substr($oid, 1);

    $oid = explode('.', $oid);

    $parent = '';
    for($i = 0; $i < count($oid); $i++)
    {
      if(!isset($nodes[$parent]))
      {
        if($ret_type == 'array') return $oid;
        return '.' . join('.', $oid);
      }
      $rec = $nodes[$parent];
      if(is_numeric($oid[$i]))
      {
        if(!isset($rec[$oid[$i]]))
        {
          if($ret_type == 'array') return $oid;
          return '.' . join('.', $oid);
        }
        $parent = $rec[$oid[$i]];
        if($format == OID_TEXT) $oid[$i] = $parent;
      }
      else
      {
        $z = array_search($oid[$i], $rec);
        if($z === false)
        {
          if($ret_type == 'array') return $oid;
          return '.' . join('.', $oid);
        }
        $parent = $rec[$z];
        if($format == OID_NUMERIC) $oid[$i] = $z;
      }
    }
    if($ret_type == 'array') return $oid;
    return '.' . join('.', $oid);
  }
?>
