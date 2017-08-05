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
 * @subpackage rfc1905
 * @version .7
 */

/**
 */
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1155.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1157.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'rfc1902.php');

define('MAX_BINDINGS', 2147483647);

define('ASN_TAG_GETBULK', 	0x05);
define('ASN_TAG_INFORM', 	0x06);
define('ASN_TAG_TRAPV2', 	0x07);
define('ASN_TAG_REPORT', 	0x08);

$ASN_TAG_DICT[0xa2] = 'rfc1905_Response';
$ASN_TAG_DICT[0xa5] = 'rfc1905_GetBulk';
$ASN_TAG_DICT[0xa6] = 'rfc1905_Inform';
$ASN_TAG_DICT[0xa7] = 'rfc1905_TrapV2';
$ASN_TAG_DICT[0xa8] = 'rfc1905_Report';
$GLOBALS["ASN_TAG_DICT"] = $ASN_TAG_DICT;

// ucd-snmp returns context-specific values at time
define('ASN_TAG_NO_SUCH_OBJECT',	0x80);
define('ASN_TAG_NO_SUCH_INSTANCE',	0x81);
define('ASN_TAG_END_OF_MIB_VIEW',	0x82);
$ASN_TAG_DICT[0x80] = 'rfc1905_NoSuchObject';
$ASN_TAG_DICT[0x81] = 'rfc1905_NoSuchInstance';
$ASN_TAG_DICT[0x82] = 'rfc1905_EndOfMibView';

/**
 * No Such Object
 *
 * This is a special type for ucd-snmp
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_NoSuchObject extends rfc1155_Null
{
 /**
  * Constructor
  */
  public function __construct()
  {
    parent::__construct();
    $this->asnTagNumber = ASN_TAG_NO_SUCH_OBJECT;
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  public function toString()
  {
    return 'No such Object';
  }
}

/**
 * No Such Instance
 *
 * This is a special type for ucd-snmp
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_NoSuchInstance extends rfc1155_Null
{
 /**
  * Constructor
  */
  public function __construct()
  {
    parent::__construct();
    $this->asnTagNumber = ASN_TAG_NO_SUCH_INSTANCE;
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  public function toString()
  {
    return 'No such Instance';
  }
}

/**
 * End Of MIB View
 *
 * This is a special type for ucd-snmp
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_EndOfMibView extends rfc1155_Null
{
 /**
  * Constructor
  */
  public function __construct()
  {
    parent::__construct();
    $this->asnTagNumber = ASN_TAG_END_OF_MIB_VIEW;
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  public function toString()
  {
    return 'End of MIB';
  }
}

/**
 * Variable Binding List
 *
 * An SNMPv2 VarBindList has a maximum size of MAX_BINDINGS
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_VarBindList extends rfc1157_VarBindList
{
 /**
  * Constructor
  *
  * @param array $value
  */
  public function __construct($value=array())
  {
    if(count($value) > MAX_BINDINGS)
      trigger_error('A VarBindList must be shorter than ' . MAX_BINDINGS, E_USER_WARNING);
    parent::__construct($value);
  }
}

/**
 * Message
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Message extends rfc1157_Message
{
 /**
  * Constructor
  *
  * @param integer $version
  * @param string $community
  * @param mixed $data
  */
  public function __construct($version=1, $community='public', $data=NULL)
  {
    parent::__construct($version, $community, $data);
  }
}

/**
 * Error Status
 *
 * An SNMPv2 Error status
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_ErrorStatus extends rfc1157_ErrorStatus
{
 /**
  * Constructor
  *
  * @param integer $value
  */
  public function __construct($value)
  {
    parent::__construct($value);
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  public function toString()
  {
    switch($this->value)
    {
      case 6: return 'Access is not permitted';
      case 7: return 'Type is incorrect';
      case 8: return 'Length is incorrect';
      case 9: return 'Encoding is incorrect';
      case 10: return 'Value is incorrect';
      case 11: return 'No creation';
      case 12: return 'Value is inconsistent';
      case 13: return 'Resourse Unavailable';
      case 14: return 'Commit Failed';
      case 15: return 'Undo Failed';
      case 16: return 'Authorization Error';
      case 17: return 'Not Writable';
      case 18: return 'Inconsistent Name';
    }
    return parent::toString();
  }
}

/**
 * PDU
 *
 * SNMPv2 PDUs are very similar to SNMPv1 PDUs
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_PDU extends rfc1157_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  public function __construct($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::__construct();
    $this->asnTagClass = ASN_TAG_CLASS_CONTEXT;

    if($errorIndex > MAX_BINDINGS)
      trigger_error('errorIndex must be <= ' . MAX_BINDINGS, E_USER_WARNING);

    $this->value = array(new rfc1902_Integer32($requestID), new rfc1905_ErrorStatus($errorStatus),
                         new rfc1155_Integer($errorIndex), new rfc1905_VarBindList($varBindList));
  }

 /**
  * ToString
  *
  * @return string value of this object
  */
  public function toString()
  {
    $req = $this->value[0]->toString();
    $err = $this->value[1]->tostring();
    $ei = $this->value[2]->toString();
    $vb = $this->value[3]->toString();
    return "rfc1905_PDU(RequestID:$req,ErrorStatus:$err,ErrorIndex:$ei,VarBind:$vb)";
  }
}

/**
 * Bulk PDU
 *
 * BulkPDU is a new type of PDU specifically for doing GetBulk requests in SNMPv2.
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_BulkPDU extends rfc1155_Sequence
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $nonRepeaters
  * @param integer $maxRepetitions
  * @param array $varBindList
  */
  public function __construct($requestID=0, $nonRepeaters=0, $maxRepetitions=0, $varBindList=array())
  {
    parent::__construct();
    $this->asnTagClass = ASN_TAG_CLASS_CONTEXT;

    if($nonRepeaters > MAX_BINDINGS)
      trigger_error('nonRepeaters must be <= ' . MAX_BINDINGS, E_USER_WARNING);
    if($maxRepetitions > MAX_BINDINGS)
      trigger_error('maxRepetitions must be <= ' . MAX_BINDINGS, E_USER_WARNING);

    $this->value = array(new rfc1902_Integer32($requestID), new rfc1155_Integer($nonRepeaters),
                         new rfc1155_Integer($maxRepetitions), new rfc1905_VarBindList($varBindList));
  }

 /**
  * Get/Set Request ID
  *
  * @param integer $value
  * @return integer
  */
  public function requestID($value=NULL)
  {
    if(!is_null($value)) $this->value[0]->value = $value;
    return $this->value[0]->value;
  }

 /**
  * Get/Set Non Repeaters
  *
  * @param integer $value
  * @return integer
  */
  public function nonRepeaters($value=NULL)
  {
    if(!is_null($value)) $this->value[1]->value = $value;
    return $this->value[1]->value;
  }

 /**
  * Get/Set Max Repetitions
  *
  * @param integer $value
  * @return integer
  */
  public function maxRepetitions($value=NULL)
  {
    if(!is_null($value)) $this->value[2]->value = $value;
    return $this->value[2]->value;
  }

 /**
  * Get/Set Var Bind List
  *
  * @param rfc1905_VarBindList $value
  * @return rfc1905_VarBindList
  */
  public function varBindList($value=NULL)
  {
    if(!is_null($value)) $this->value[3]->value = $value;
    return $this->value[3]->value;
  }

 /**
  * Decode Contents
  *
  * Decode octet stream
  *
  * @param string $stream
  * @return rfc1905_BulkPDU
  */
  public function decodeContents($stream) // Decode into a BulkPDU object
  {
    parent::decodeContents($stream);
    if(count($this->value) != 4)
      trigger_error('Malformed BulkPDU: Incorrect length ' . count($this->value), E_USER_WARNING);
    return $this;
  }
}

/**
 * Get Request
 *
 * An SNMPv2 Get Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Get extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  public function __construct($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::__construct($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_GET;
  }
}

/**
 * Get Next Request
 *
 * An SNMPv2 Get Next Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_GetNext extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  public function __construct($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::__construct($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_GETNEXT;
  }
}

/**
 * Response
 *
 * An SNMPv2 Response PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Response extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  public function __construct($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::__construct($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_RESPONSE;
  }
}

/**
 * Set Request
 *
 * An SNMPv2 set Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Set extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  public function __construct($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::__construct($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_SET;
  }
}

/**
 * Get Bulk Request
 *
 * An SNMPv2 Get Bulk Request PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_GetBulk extends rfc1905_BulkPDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $nonRepeaters
  * @param integer $maxRepetitions
  * @param array $varBindList
  */
  public function __construct($requestID=0, $nonRepeaters=0, $maxRepetitions=0, $varBindList=array())
  {
    parent::__construct($requestID, $nonRepeaters, $maxRepetitions, $varBindList);
    $this->asnTagNumber = ASN_TAG_GETBULK;
  }
}

/**
 * Inform
 *
 * An SNMPv2 Inform PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Inform extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  public function __construct($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::__construct($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_INFORM;
  }
}

/**
 * Trap
 *
 * An SNMPv2 Trap PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Trap extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  public function __construct($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::__construct($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_TRAPV2;
  }
}

/**
 * Report
 *
 * An SNMPv2 Report PDU
 *
 * @package phpSNMP
 * @subpackage rfc1905
 */
class rfc1905_Report extends rfc1905_PDU
{
 /**
  * Constructor
  *
  * @param integer $requestID
  * @param integer $errorStatus
  * @param integer $errorIndex
  * @param array $varBindList
  */
  public function __construct($requestID=0, $errorStatus=0, $errorIndex=0, $varBindList=array())
  {
    parent::__construct($requestID, $errorStatus, $errorIndex, $varBindList);
    $this->asnTagNumber = ASN_TAG_REPORT;
  }
}
?>
