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

require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'oid_format.php');

/**
 * Dump a string in Hex and stripped ascii
 *
 * @param string $string
 * @return string
 */
function hexdump($string)
{
  $ret = '';
  for($i = 0; $i < strlen($string); $i++)
    $ret .= str_pad(dechex(ord($string{$i})), 2, '0', STR_PAD_LEFT) . ' ';
  $ret .= '[';
  for($i = 0; $i < strlen($string); $i++)
  {
    $o = ord($string{$i});
    if($o < 32 || $o > 127) $ret .= '.';
    else $ret .= chr($o);
  }
  return $ret . "]\n";
}

/**
 * Convert a hex string to raw data
 *
 * @param string $hex
 * @return string
 */
function hexbin($hex) // convert a hex string to raw data
{
  $ret = '';
  foreach(explode(' ', $hex) as $c)
    $ret .= chr(hexdec($c));
  return $ret;
}

/**
 * Divide with Remainder
 *
 * This public function uses float operation to do what was done with bit operations on integers previously.
 * This is the result of PHP automatically converting large numbers to floats. PHP has no unsigned longs.
 * One advantage is that it can handle 64 bit integers, although some precision is lost.
 *
 * @param integer $numerator
 * @param integer $denominator
 * @return array(quotient, remainder)
 */
function divide_with_remainder($numerator, $denominator)
{
  $q = intval($numerator / $denominator);
  $r = intval(($numerator / $denominator - $q) * $denominator);
  return array($q, $r);
}

define('ASN_TAG_CLASS_UNIVERSAL',	0x00);
define('ASN_TAG_CLASS_APPLICATION',	0x40);
define('ASN_TAG_CLASS_CONTEXT',		0x80);
define('ASN_TAG_CLASS_PRIVATE',		0xC0);

define('ASN_TAG_FORMAT_PRIMITIVE',	0x00);
define('ASN_TAG_FORMAT_CONSTRUCTED',	0x20);

define('ASN_TAG_BOOLEAN',		0x01);
define('ASN_TAG_INTEGER',		0x02);
define('ASN_TAG_OCTETSTRING',		0x04);
define('ASN_TAG_NULL',			0x05);
define('ASN_TAG_OBJECTID',		0x06);
define('ASN_TAG_SEQUENCE',		0x10);

define('ASN_TAG_IPADDRESS',		0x00);
define('ASN_TAG_COUNTER',		0x01);
define('ASN_TAG_GUAGE',			0x02);
define('ASN_TAG_TIMETICKS',		0x03);
define('ASN_TAG_OPAQUE',		0x04);

$ASN_TAG_DICT[0x01] = 'rfc1155_Boolean';
$ASN_TAG_DICT[0x02] = 'rfc1155_Integer';
$ASN_TAG_DICT[0x04] = 'rfc1155_OctetString';
$ASN_TAG_DICT[0x05] = 'rfc1155_Null';
$ASN_TAG_DICT[0x06] = 'rfc1155_ObjectID';
$ASN_TAG_DICT[0x30] = 'rfc1155_Sequence';
$ASN_TAG_DICT[0x40] = 'rfc1155_IPAddress';
$ASN_TAG_DICT[0x41] = 'rfc1155_Counter';
$ASN_TAG_DICT[0x42] = 'rfc1155_Guage';
$ASN_TAG_DICT[0x43] = 'rfc1155_TimeTicks';
$ASN_TAG_DICT[0x44] = 'rfc1155_Opaque';
$GLOBALS["ASN_TAG_DICT"] = $ASN_TAG_DICT;

/**
 * Asn1Objects
 *
 * Base class for all Asn1Objects. This is only intended to support a specific subset of ASN1 stuff as
 * defined by the RFCs to keep things as simple as possible.
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_Asn1Object
{
  var $asnTagClass = ASN_TAG_CLASS_UNIVERSAL;
  var $asnTagFormat= ASN_TAG_FORMAT_PRIMITIVE;
  var $asnTagNumber = NULL;

  var $value = NULL;

 /**
  * Constructor
  */
  public function __construct(){}

 /**
  * Encode Asn1Object
  *
  * encode() this Asn1Object using BER
  *
  * @return string encoded object
  */
  public function encode()
  {
    $contents = $this->encodeContents();
    return $this->encodeIdentifier() . $this->encodeLength(strlen($contents)) . $contents;
  }

 /**
  * Decode Tag
  *
  * Decode a BER tag field, returning the tag and the remainder of the stream
  *
  * @param string $stream
  * @return array (tag, remaining_stream)
  */
  public function decodeTag($stream)
  {
    $tag = ord($stream{0});
    $n = 1;
    if(($tag & 0x1F) == 0x1F)
    {
      /* A large tag is encoded using concatenated 7-bit values over the following octets, ignoring the initial 5 bits
         in the first octet.  The 8th bit represents a follow-on. */
      $tag = 0;
      do
      {
        $byte = ord($stream{$n});
        $tag = $tag * 128 + ($byte & 0x7F);
        $n += 1;
      } while($byte & 0x80);
    }
    return array($tag, substr($stream, $n));
  }

 /**
  * Decode Length
  *
  * Decode a BER length field, returing the length and the remainder of the stream
  *
  * @param string $stream
  * @return array (length, remaining_stream)
  */
  public function decodeLength($stream)
  {
    $length = ord($stream{0});
    $i = 1;
    if($length & 0x80)
    {
      // Multi-Octet length encoding.  The first octet represents the run-length (the number of octets used to build the length)
      $run = $length & 0x7F;
      $length = 0;
      for($i = 1; $i <= $run; $i++)
        $length = $length * 256 + ord($stream{$i});
    }
    return array($length, substr($stream, $i));
  }

 /**
  * Decode Stream
  *
  * decode() an octet stream into a sequence of Asn1Objects
  *
  * @param string $stream
  * @return array of rfc1155_Asn1Object
  */
  public function decode($stream)
  {
    /* This method should be overridden by subclasses to define how to decode one of themselves from a fixed length stream.  This
       general case method looks at the identifier at the beginning of a stream of octets and uses the appropriate decode() method
       of that known object.  Attempts to decode() an unknown object type result in an error. */
    if(!is_string($stream))
    {
      trigger_error('stream should be of a string, not a ' . gettype($stream), E_USER_WARNING);
      return array();
    }

    $objects = array();
    while(strlen($stream) > 0)
    {

      list($tag, $stream) = $this->decodeTag($stream);
      list($length, $stream) = $this->decodeLength($stream);

      $objectData = substr($stream, 0, $length);
      $stream = substr($stream, $length);

      global $ASN_TAG_DICT;
      if(isset($ASN_TAG_DICT[$tag]))
      {
        $decoder = $ASN_TAG_DICT[$tag];
        $o = new $decoder();
        $objects[] =  $o->decodeContents($objectData);
      }
      else
        trigger_error("Unknown ASN.1 Type 0x" . dechex($tag), E_USER_WARNING);
    }
    return $objects;
  }

 /**
  * Encode Contents
  *
  * encodeContents must be overridden by subclasses to encode the contents of a particular type
  *
  * @return string
  */
  public function encodeContents()
  {
    trigger_error('encodeContents not implemented', E_USER_ERROR);
  }

 /**
  * Encode Identifier
  *
  * encodeIdentifier() returns encoded identifier octets for this object.  Section 6.3 of ITU-T-X.209
  *
  * @return string
  */
  public function encodeIdentifier()
  {
    if($this->asnTagNumber < 0x1F)
    {
      return chr($this->asnTagClass | $this->asnTagFormat | $this->asnTagNumber);
    }
    else
    {
      /* Encode each number of the asnTagNumber from 31 upwards as a sequence of 7-bit numbers with bit 8 set to 1 for
          all but the last octet. Bit 8 set to 0 signifies the last octet of the Identifier octets */

      // encode the first octet
      $resultlist = array();
      $resultlist[] = chr($this->asnTagClass | $this->asnTagFormat | 0x1F);

      // encode each subsequent octet
      $integer = $this->asnTagNumber;
      while($integer != 0)
      {
        list($integer, $remainder) = divide_with_remainder($integer, 256);
        $resultlist[] = chr($remainder);
      }

      return join('', $resultlist);
    }
  }

 /**
  * Encode Length
  *
  * encodeLength() takes the length of the contents and produces the encoding for that length.  Section 6.3 of ITU-T-X.209
  *
  * define('SNMP_SHORT_INT_LENGTH', 1) to encode as short; needed by some Cisco software
  *
  * @param integer $length
  * @return string
  */
  public function encodeLength($length)
  {
    if(defined('SNMP_SHORT_INT_LENGTH')) // hack to be compatible with Cisco software
    {
      list($a, $b) = divide_with_remainder($length, 256);
      return chr(0x82) . chr($a) . chr($b);
    }
    elseif($length < 127)
      return chr($length & 0xff);
    else
    {
      /* Long form - Octet one is the number of octets used to encode the length It has bit 8 set to 1 and the remaining 7 bits are
         used to encode the number of octets used to encode the length Each subsequent octet uses all 8 bits to encode the length */
      $resultlist = array();
      $numOctets = 0;
      while($length > 0)
      {
        list($length, $remainder) = divide_with_remainder($length, 256);
        array_unshift($resultlist, chr($remainder));
        $numOctets++;
      }

      // Add a 1 to the front of the octet
      $numOctets = $numOctets | 0x80;
      array_unshift($resultlist, chr($numOctets & 0xff));

      return join('', $resultlist);
    }
  }

 /**
  * Encode End of Contents
  *
  * @return string
  */
  public function encodeEndOfContents()
  {
     return "\000\000";
  }
}

/**
 * rfc1155 Boolean
 *
 * An ASN.1 Boolean type
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_Boolean extends rfc1155_Asn1Object
{
 /**
  * Constructor
  *
  * @param boolean $value
  */
  public function __construct($value=true)
  {
    $this->asnTagClass = ASN_TAG_CLASS_UNIVERSAL;
    $this->asnTagNumber = ASN_TAG_BOOLEAN;

    $this->value = ($value) ? true : false;
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  public function toString()
  {
    return ($this->value) ? 'true' : 'false';
  }

 /**
  * Encode Contents
  *
  * encode into an octet stream
  *
  * @return string
  */
  public function encodeContents()
  {
    trigger_error('encodeContents not written yet', E_USER_ERROR);
  }

 /**
  * Decode Contents
  *
  * Decode octet stream
  *
  * @param string $stream
  * @return rfc1155_Boolean
  */
  public function decodeContents(/*$stream*/)
  {
    trigger_error('decodeContents not written yet', E_USER_ERROR);
    return $this;
  }
}

/**
 * rfc1155 Integer
 *
 * An ASN.1 Integer type
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_Integer extends rfc1155_Asn1Object
{
 /**
  * Constructor
  *
  * @param integer $value
  */
  public function __construct($value=0)
  {
    $this->asnTagClass = ASN_TAG_CLASS_UNIVERSAL;
    $this->asnTagNumber = ASN_TAG_INTEGER;
    $this->check_range($value);
    $this->value = $value;
  }

 /**
  * Check range for integer value
  *
  * @param integer $value
  * @param integer $min
  * @param integer $max
  */
  public function check_range($value, $min=NULL, $max=NULL)
  {
    static $MINVAL = -2147483648;
    static $MAXVAL = 2147483647;
    if(!is_null($min)) $MINVAL = $min;
    if(!is_null($max)) $MAXVAL = $max;

    $value = intval($value);
    if(is_null($min) && is_null($max) && ($value < $MINVAL || $value > $MAXVAL))
    {
      trigger_error("Integer value of $value (".gettype($value).") is out of bounds ($MINVAL to $MAXVAL)", E_USER_WARNING);
    }
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  public function toString()
  {
    return $this->value;
  }

 /**
  * Encode Contents
  *
  * encode into an octet stream
  *
  * @return string
  */
  public function encodeContents()
  {
    // We handle two special cases otherwise we handle positive and negative numbers independently

    $integer = $this->value;

    if($integer == 0)
      return "\000";
    elseif($integer == -1)
      return "\377";
    elseif($integer > 0)
    {
      $result = array();
      while($integer != 0)
      {
        list($integer, $remainder) = divide_with_remainder($integer, 256);
        array_unshift($result, $remainder);
      }
      if($result[0] & 0x80)
        array_unshift($result, 0);
      return join('', array_map('chr', $result));
    }
    else
    {
      $result = array();
      while($integer != 0)
      {
        list($integer, $remainder) = divide_with_remainder($integer, 256);
        array_unshift($result, $remainder);
      }
      if($result[0] & 0x80 != 0x80)
        array_unshift($result, 0);
      return join('', array_map('chr', $result));
    }
  }

 /**
  * Decode Contents
  *
  * Decode octet stream
  *
  * @param string $stream
  * @return rfc1155_Integer
  */
  public function decodeContents($stream)
  {
    $this->value = 0;
    $byte = ord($stream{0});
    if(($byte & 0x80) == 0x80)
    {
      $negbit = 0x80;
      $this->value = $byte & 0x7f;
      for($i = 1; $i < strlen($stream); $i++)
      {
        $negbit *= 256;
        $this->value = $this->value * 256 + ord($stream{$i});
      }
      $this->value = $this->value - $negbit;
    }
    else
    {
      $this->value = $byte;
      for($i = 1; $i < strlen($stream); $i++)
        $this->value = $this->value * 256 + ord($stream{$i});
    }
    return $this;
  }
}

/**
 * rfc1155 Octet String
 *
 * An ASN.1 Octet String type
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_OctetString extends rfc1155_Asn1Object
{
 /**
  * Constructor
  *
  * @param strin $value
  */
  public function __construct($value='')
  {
    $this->asnTagClass = ASN_TAG_CLASS_UNIVERSAL;
    $this->asnTagNumber = ASN_TAG_OCTETSTRING;
    $this->value = $value;
  }

 /**
  * Is Printable?
  *
  * Decides if its value is printable
  *
  * @return boolean
  */
  public function is_printable()
  {
    for($i = strlen($this->value) - 1; $i >= 0; $i--)
    {
      if($this->value{$i} != "\n" && $this->value{$i} != "\t" && $this->value{$i} != "\r")
      {
        if(ord($this->value{$i}) < 16 || ord($this->value{$i}) > 127)
        {
          return false;
        }
      }
    }
    return true;
  }

 /**
  * to Hex
  *
  * Converts its value to a hex string
  *
  * @return string
  */
  public function toHex()
  {
    $ret = '';
    for($i = 0; $i < strlen($this->value); $i++)
      $ret .= str_pad(dechex(ord($this->value{$i})), 2, '0', STR_PAD_LEFT) . ' ';
    return trim($ret);
  }

 /**
  * toString
  *
  * @return string
  */
  public function toString()
  {
    if($this->is_printable())
      return $this->value;
    else
      return $this->toHex();
  }

 /**
  * Encode Contents
  *
  * encode into an octet stream
  *
  * @return string
  */
  public function encodeContents()
  {
    // An OctetString is already encoded. Whee!
    return $this->value;
  }

 /**
  * Decode Contents
  *
  * Decode octet stream
  *
  * @param string $stream
  * @return rfc1155_OctetString
  */
  public function decodeContents($stream)
  {
    // An OctetString is already decoded. Whee!
    $this->value = $stream;
    return $this;
  }
}

/**
 * rfc1155 Object Identifier (oid)
 *
 * An ASN.1 Object Identifier type
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_ObjectID extends rfc1155_Asn1Object
{
 /**
  * Constructor
  *
  * @param string $value
  */
  public function __construct($value=array())
  {
    // Create an ObjectID - value is a list of subids as a string or list
    $this->asnTagClass = ASN_TAG_CLASS_UNIVERSAL;
    $this->asnTagFormat = ASN_TAG_FORMAT_PRIMITIVE;
    $this->asnTagNumber = ASN_TAG_OBJECTID;

    if(is_string($value))
      $this->value = explode('.', $value);
    elseif(is_array($value))
      $this->value = $value;
    elseif(is_null($value))
      $this->value = array();
    else
      trigger_error('Unknown type passed as OID', E_USER_WARNING);

    $this->value = oid_format($this->value, OID_NUMERIC);

    foreach($this->value as $subid)
      if($subid < 0 || $subid > 0x7FFFFFFF)
        trigger_error("SubID $subid out of range", E_USER_WARNING);
  }

 /**
  * toString
  *
  * @return string
  */
  public function toString()
  {
    return '.' . join('.', $this->value);
  }

 /**
  * Encode Contents
  *
  * encode into an octet stream
  *
  * @return string
  */
  public function encodeContents()
  {
    $result = array();
    $idlist = $this->value;

    // Do the bit with the first 2 subids; section 22.4 of X.209
    $idlist = array_reverse($idlist);
    $subid1 = (array_pop($idlist) * 40) + array_pop($idlist);
    $idlist = array_reverse($idlist);
    array_unshift($idlist, $subid1);
    foreach($idlist as $subid)
    {
      if(!is_numeric($subid))
      {
        trigger_error('Unable to encode non-numeric OID', E_USER_WARNING);
        return '';
      }
      if($subid < 128)
        $result[] = chr($subid & 0x7f);
      else
      {
        list($subid, $remainder) = divide_with_remainder($subid, 128);
        $r = array(chr($remainder));
        while($subid > 0)
        {
          list($subid, $remainder) = divide_with_remainder($subid, 128);
          $r[] = chr(0x80 | $remainder);
        }
        for($i = count($r) - 1; $i >=0; $i--) $result[] = $r[$i];
      }
    }
    return join('', $result);
  }

 /**
  * Decode Contents
  *
  * Decode octet stream
  *
  * @param string $stream
  * @return rfc1155_ObjectID
  */
  public function decodeContents($stream)
  {
    $this->value = array();

    if(strlen($stream) == 0)
    {
      trigger_error('Stream of zero length in ' . get_class($this), E_USER_WARNING);
      return $this;
    }

    // Do the funky decode of the first octet
    if(ord($stream{0}) < 128)
    {
      $this->value[] = intval(ord($stream{0}) / 40);
      $this->value[] = ord($stream{0}) % 40;
    }
    else
    {
       /* I haven't bothered putting in the convoluted logic here because the highest likely assignment for the first
          octet is 83 according to Annex B of X.208 Those X.209 does give as an example 2.100.3, which is kinda stupid.
          Actually, a lot of the space-saving encodings, like this first octet, are a real PITA later on.  So yeah,
          stuff it, we'll just raise an exception. */

      trigger_error('NotImplementedError: First octet is > 128! Unsupported oid detected', E_USER_ERROR);
      return $this;
    }

    // Decode the rest of the octets
    $n = 1;
    while($n < strlen($stream))
    {
      $subid = ord($stream{$n});
      $n += 1;

      // If bit 8 is not set, this is the last octet of this subid
      // If bit 8 is set, the subid spans this octet and the ones afterwards, up until bit 8 isn't set.
      if(($subid & 0x80) == 0x80)
      {
        $val = $subid & 0x7f;
        while(($subid & 0x80) == 0x80)
        {
          $subid = ord($stream{$n});
          $n += 1;
          $val = $val * 128 + ($subid & 0x7f);
        }
        $this->value[] = $val;
      }
      else
      {
        $this->value[] = $subid;
      }
    }
    return $this;
  }
}

/**
 * rfc1155 Null
 *
 * An ASN.1 Null type
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_Null extends rfc1155_Asn1Object // An ASN.1 Object Identifier type
{
 /**
  * Constructor
  */
  public function __construct()
  {
    $this->asnTagClass = ASN_TAG_CLASS_UNIVERSAL;
    $this->asnTagFormat = ASN_TAG_FORMAT_PRIMITIVE;
    $this->asnTagNumber = ASN_TAG_NULL;
  }

 /**
  * toString
  *
  * @return string
  */
  public function toString()
  {
    return '';
  }

 /**
  * Encode Contents
  *
  * encode into an octet stream
  *
  * @return string
  */
  public function encodeContents()
  {
    return '';
  }

 /**
  * Decode Contents
  *
  * Decode octet stream
  *
  * @param string $stream
  * @return rfc1155_Null
  */
  public function decodeContents($stream)
  {
    if(strlen($stream) != 0)
      trigger_error('Input stream too long for ' . get_class($this), E_USER_WARNING);
    return $this;
  }
}

/**
 * rfc1155 Sequence
 *
 * An ASN.1 Sequence type
 *
 * A Sequence is basically a list of name, value pairs with the name being an object Type and the
 * value being an instance of an Asn1Object of that Type.
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_Sequence extends rfc1155_Asn1Object
{
 /**
  * Constructor
  *
  * @param array $value list of rfc1155_Asn1Object
  */
  public function __construct($value=array())
  {
    $this->asnTagClass = ASN_TAG_CLASS_UNIVERSAL;
    $this->asnTagFormat = ASN_TAG_FORMAT_CONSTRUCTED;
    $this->asnTagNumber = ASN_TAG_SEQUENCE;
    $this->value = $value;
  }

 /**
  * Encode Contents
  *
  * encode into an octet stream
  *
  * @return string
  */
  public function encodeContents()
  {
    // To encode a Sequence, we simply encode() each sub-object in turn.
    $resultlist = array();
    foreach($this->value as $elem)
      $resultlist[] = $elem->encode();
    return join('', $resultlist);
  }

 /**
  * Decode Contents
  *
  * Decode octet stream
  *
  * @param string $stream
  * @return rfc1155_Sequence
  */
  public function decodeContents($stream)
  {
    $this->value = $this->decode($stream);
    return $this;
  }

 /**
  * toString
  *
  * @return string
  */
  public function toString()
  {
    $vals = array();
    foreach($this->value as $v) $vals[] = get_class($v) . '(' . $v->toString() . ')';
    $vals = join(',', $vals);
    return get_class($this) . "($vals)";
  }
}

/**
 * rfc1155 SequenceOf
 *
 * An ASN.1 SequenceOf type
 *
 * A Sequence is basically a list of name, value pairs with the name being an object Type and the
 * value being an instance of an Asn1Object of that Type.
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_SequenceOf extends rfc1155_Sequence
{
  // A SequenceOf is a special kind of sequence that places a constraint on the kind of objects it can contain.  It is variable in length.

  var $componentType;

 /**
  * Constructor
  *
  * @param string $componentType name of object type used
  * @param array $value list of rfc1155_Asn1Object of type $componentType
  */
  public function __construct($componentType='rfc1155_asn1Object', $value=array())
  {
    parent::__construct($value);
    $this->asnTagClass = ASN_TAG_CLASS_UNIVERSAL;
    $this->asnTagFormat = ASN_TAG_FORMAT_CONSTRUCTED;
    $this->asnTagNumber = ASN_TAG_SEQUENCE;

    $this->componentType = $componentType;

    // Add each item in the list to ourselves, which automatically checks each one to ensure it is of the correct type.
    $this->value = array();

    foreach($value as $item)
      $this->append($item);
  }

 /**
  * Append
  *
  * Add an object to this sequence
  *
  * @param rfc1155_Asn1Object object to add
  */
  public function append($value)
  {
    if(!is_a($value, $this->componentType))
    {
      if(is_subclass_of(new $this->componentType(), get_class($value)))
      {

// broken way of doing this!
        $v = $value->value;
        $value = new $this->componentType();
        $value->value = $v;
      }
      else
        trigger_error(get_class($this) . ' cannot contain components of type: ' . get_class($value), E_USER_WARNING);
    }
    $this->value[] = $value;
  }
}

/**
 * rfc1155 IPAddress
 *
 * An ASN.1 IPAddress type
 *
 * An IpAddress is a special type of OctetString.  It represents a 32-bit internet address as an OctetString of length 4, in network byte order.
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_IPAddress extends rfc1155_OctetString
{
 /**
  * Constructor
  *
  * @param mixed $value (can be array, long, hostname or ip address)
  */
  public function __construct($value='0.0.0.0')
  {
    parent::__construct($value);
    $this->asnTagClass = ASN_TAG_CLASS_APPLICATION;
    $this->asnTagFormat = ASN_TAG_FORMAT_PRIMITIVE;
    $this->asnTagNumber = ASN_TAG_IPADDRESS;

    if(is_array($value))
    {
      if(count($value) != 4)
        trigger_error('IPAddress must be of length 4', E_USER_WARNING);
      $value = join('.', $value);
    }

    if(strpos($value, '.') !== false) // string
    {
      $h = ip2long($value);
      if($h == -1 || $h === false)
        $value = ip2long(gethostbyname($value));
      else
        $value = $h;
    }
    $this->value = long2ip($value);
  }

 /**
  * toString
  *
  * @return string
  */
  public function toString()
  {
    return $this->value;
  }

 /**
  * Encode Contents
  *
  * encode into an octet stream
  *
  * @return string
  */
  public function encodeContents()
  {
    $ret = '';
    $value = explode('.', $this->value);
    for($i = 0; $i < 4; $i++)
      $ret .= chr($value[$i]);
    return $ret;
  }

 /**
  * Decode Contents
  *
  * Decode octet stream
  *
  * @param string $stream
  * @return rfc1155_IPAddress
  */
  public function decodeContents($stream)
  {
    $this->value = ord($stream{0}) . '.' . ord($stream{1}) . '.' . ord($stream{2}) . '.' . ord($stream{3});
    return $this;
  }
}

/**
 * rfc1155 NetworkAddress
 *
 * An ASN.1 NetworkAddress type
 *
 * A Network Address is a CHOICE with only one possible value: internet
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_NetworkAddress extends rfc1155_IPAddress
{
//  var $name;

 /**
  * Constructor
  *
  * @param mixed $value (can be array, long, hostname or ip address)
  */
  public function __construct($value)
  {
    parent::__construct($value);
//    $this->name = 'internet';
  }
}

/**
 * rfc1155 Counter
 *
 * An ASN.1 Counter type
 *
 * A counter starts at zero and keeps going to a maximum integer value of 2^32-1 where it wraps back to zero.
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_Counter extends rfc1155_Integer
{
 /**
  * Constructor
  *
  * @param integer $value
  */
  public function __construct($value=0)
  {
    $this->check_range($value, 0, 4294967295);
    parent::__construct($value);
    $this->asnTagClass = ASN_TAG_CLASS_APPLICATION;
    $this->asnTagFormat = ASN_TAG_FORMAT_PRIMITIVE;
    $this->asnTagNumber = ASN_TAG_COUNTER;
  }

 /**
  * Decode Contents
  *
  * Decode octet stream
  *
  * Some SNMP stacks encode Counters incorrectly resulting in a negative value. There are two remedies:
  *   if you define('SNMP_ABS_COUNTER', 1), we take the absolute value of the result.
  *   else, we ignore the fact that the first bit is high and decode it as if it was positive.
  *
  * @param string $stream
  * @return rfc1155_Counter
  */
  public function decodeContents($stream)
  {
    if(defined('SNMP_ABS_COUNTER')) // hack to be compatible with Cisco software
    {
      /* Some agents encode Counters incorrectly (hello Solaris) as a negative number.  I'm assuming most SNMP libraries don't
         notice the problem because the are written in C and cast the result to an unsigned int - problem solved (if
         accidentally).  This ugly hack on their behalf flips the value over to the positive world. */
      parent::decodeContents($stream);
      $this->value = abs($this->value);
    }
    else
    {
      $this->value = 0;
      for($i = 0; $i < strlen($stream); $i++)
        $this->value = $this->value * 256 + ord($stream{$i});
    }
    return $this;
  }
}

/**
 * rfc1155 Guage
 *
 * An ASN.1 Guage type
 *
 * A Guage is a non negative integer.  It may increase or decrease. It latches at a maximum value.
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_Guage extends rfc1155_Integer
{
 /**
  * Constructor
  *
  * @param integer $value
  */
  public function __construct($value=0)
  {
    $this->check_range($value, 0, 4294967295);
    parent::__construct($value);
    $this->asnTagClass = ASN_TAG_CLASS_APPLICATION;
    $this->asnTagFormat = ASN_TAG_FORMAT_PRIMITIVE;
    $this->asnTagNumber = ASN_TAG_GUAGE;
  }
}

/**
 * rfc1155 TimeTicks
 *
 * An ASN.1 TimeTicks type
 *
 * TimeTicks is the number of hundredths of a second since an epoch, specified at object creation time
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_TimeTicks extends rfc1155_Integer
{
//  var $epoch;

 /**
  * Constructor
  *
  * @param integer $value
  */
  public function __construct($value=0/*, $epoch=NULL*/)
  {
    $this->check_range($value, 0, 4294967295);
    parent::__construct($value);
    $this->asnTagClass = ASN_TAG_CLASS_APPLICATION;
    $this->asnTagFormat = ASN_TAG_FORMAT_PRIMITIVE;
    $this->asnTagNumber = ASN_TAG_TIMETICKS;
//    $this->epoch = $epoch;
  }
}

/**
 * rfc1155 Opaque
 *
 * An ASN.1 Opaque type
 *
 * Opaque is a fun type that allows you to pass arbitrary ASN.1 encoded stuff in an object. The value is some ASN.1 syntax
 * encoded using BER which this object encodes as an OctetString.  We don't do any decoding of this object because we don't
 * have to, and that makes this all much quicker.
 *
 * @package phpSNMP
 * @subpackage rfc1155
 */
class rfc1155_Opaque extends rfc1155_OctetString
{
 /**
  * Constructor
  *
  * @param string $value
  */
  public function __construct($value)
  {
    parent::__construct($value);
  }
}
?>
