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

  set_time_limit(0);
  ini_set('memory_limit', '256M');
  error_reporting(E_ALL);

  $mc = new mib_compiler();
  $mc->add_mibs('/usr/share/snmp/mibs');
  $mc->compile();

/**
 * Asn1Objects
 *
 * Base class for all Asn1Objects. This is only intended to support a specific subset of ASN1 stuff as
 * defined by the RFCs to keep things as simple as possible.
 *
 * @package phpSNMP
 * @subpackage mib_compiler
 */
  class mib_compiler
  {
    var $parsed = array();
    var $outfile = 'oid_format.data';

   /**
    * Constructor
    */
    public function __construct()
    {
    }

   /**
    * Add mibs
    *
    * @param string $path
    */
    public function add_mibs($path)
    {
      foreach(glob("$path/*") as $mib)
      {
        if(is_dir($mib))
          $this->add_mibs($mib);
        else
          $this->add_mib($mib);
      }
    }

   /**
    * Add a mib
    *
    * @param string $filename
    */
    public function add_mib($filename)
    {
      echo "Loading $filename\n";
      $this->parse(file_get_contents($filename));
    }

   /**
    * Compile mibs
    */
    public function compile()
    {
      echo 'Found ' . count($this->parsed) . " objects\n";
      echo "Building node list\n";

      $nodes[''] = array(1=>'iso');
      $found['iso'] = 1;
      $found[''] = 1;
      foreach($this->parsed as $obj)
      {
        if(isset($obj['VALUE'][0]) && !is_numeric($obj['VALUE'][0]))
        {
          if(isset($obj['VALUE'][1]) && is_numeric($obj['VALUE'][1]))
          {
            $nodes[$obj['VALUE'][0]][$obj['VALUE'][1]] = $obj['NAME'];
            $found[$obj['NAME']] = 1;
          }
        }
      }

      echo "Trimming disconnected nodes\n";
      foreach(array_keys($nodes) as $key)
      {
        if(!isset($found[$key]))
        {
          echo "deleting $key\n";
          unset($nodes[$key]);
        }
      }

      echo "Writing {$this->outfile}\n";
      $fp = fopen($this->outfile, 'w');
      fputs($fp, serialize($nodes));
      fclose($fp);
    }

    // // // // // // // // //
    // NOTHING PUBLIC BELOW //
    // // // // // // // // //

   /**
    * Parse a MIB file
    *
    * @param string $mibtext
    * @param boolean $full
    */
    public function parse($mibtext, $full=false)
    {
      $tokens = $this->get_tokens($mibtext);
      $cnt = count($tokens);
      echo "Found $cnt tokens\n";
      $rec = array();
      for($index = 0; $index < $cnt; $index++)
      {
        echo number_format(100 *$index / $cnt, 2) . "%                                \r";
        if($tokens[$index] == 'OBJECT-IDENTITY' || $tokens[$index] == 'OBJECT-TYPE' || $tokens[$index] == 'MODULE-IDENTITY')
        {
          if($tokens[$index-1] != ',' && $tokens[$index+1] != 'FROM' && $tokens[$index+1] != 'MACRO')
          {
            if(isset($rec['NAME']) && isset($rec['VALUE'])) $this->parsed[] = $rec;
            $rec = array('NAME'=>$tokens[$index-1]);
          }
        }
        elseif($tokens[$index] == 'OBJECT')
        {
          if($tokens[$index+1] == 'IDENTIFIER' && $tokens[$index-1] != '(' && $tokens[$index-1] != '::=' && $tokens[$index-1] != 'SYNTAX' && $tokens[$index-2] != '(')
          {
            if(isset($rec['NAME']) && isset($rec['VALUE'])) $this->parsed[] = $rec;
            $rec = array('NAME'=>$tokens[$index-1]);
          }
        }
        elseif($tokens[$index] == '{')
          $this->parse_bracket_token($tokens, $index, '{', '}');
        elseif(isset($rec['NAME']))
        {
          if($tokens[$index] == '::=')
          {
            $rec['VALUE'] = $this->parse_simple_token($tokens, $index);
            $this->parsed[] = $rec;
            $rec = array();
          }
          elseif($full)
          {
            if($tokens[$index] == 'ACCESS')
              $rec['ACCESS'] = $this->parse_simple_token($tokens, $index, array('read-only', 'not-accessible', 'read-write'));
            elseif($tokens[$index] == 'DEFVAL')
              $rec['DEFVAL'] = $this->parse_simple_token($tokens, $index);
            elseif($tokens[$index] == 'DESCRIPTION')
              $rec['DESCRIPTION'] = $tokens[++$index];
            elseif($tokens[$index] == 'INDEX')
              $rec['INDEX'] = $this->parse_simple_token($tokens, $index);
            elseif($tokens[$index] == 'MAX-ACCESS')
              $rec['MAX-ACCESS'] = $this->parse_simple_token($tokens, $index, array('read-only', 'not-accessible', 'read-write', 'read-create', 'accessible-for-notify'));
            elseif($tokens[$index] == 'REFERENCE')
              $rec['REFERENCE'] = $this->parse_simple_token($tokens, $index);
            elseif($tokens[$index] == 'STATUS')
              $rec['STATUS'] = $this->parse_simple_token($tokens, $index, array('current', 'deprecated', 'obsolete', 'mandatory'));
            elseif($tokens[$index] == 'SYNTAX')
              $rec['SYNTAX'] = $this->parse_SYNTAX_token($tokens, $index);
            elseif($tokens[$index] == 'UNITS')
              $rec['UNITS'] = $this->parse_simple_token($tokens, $index);
          }
        }
      }
      echo number_format(100, 2) . "%                                \r";
      if(isset($rec['NAME']) && isset($rec['VALUE'])) $this->parsed[] = $rec;
    }

   /**
    * Get Tokens
    *
    * @param string $text
    * @return array
    */
    public function get_tokens($text)
    {
      $in_quote = false;
      $in_comment = false;
      $token = '';
      $tokens = array();
      $length = strlen($text);
      for($i = 0; $i < $length; $i++)
      {
        if($in_quote)
        {
          if($text{$i} == '"')
          {
            $in_quote = false;
            if($token != '')
            {
              $tokens[] = $token;
              $token = '';
            }
          }
          else
            $token .= $text{$i};
        }
        elseif($in_comment)
        {
          if($text{$i} == "\n" || $text{$i} == "\r")
            $in_comment = false;
        }
        else
        {
          switch($text{$i})
          {
            case ':':
              if($text{$i+1} == ':' && $text{$i+2} == '=')
              {
                if($token != '')
                {
                  $tokens[] = $token;
                 $token = '';
                }
                $tokens[] = '::=';
                $i += 2;
              }
              else
                $token .= $text{$i};
              break;
            case '.':
              if($text{$i+1} == '.')
              {
                if($token != '')
                {
                  $tokens[] = $token;
                  $token = '';
                }
                $tokens[] = '..';
                $i++;
              }
              else
                $token .= $text{$i};
              break;
            case ',':
            case ';':
            case '{':
            case '}':
            case '(':
            case ')':
            case '|':
              if($token != '')
              {
                $tokens[] = $token;
                $token = '';
              }
              $tokens[] = $text{$i};
              break;
            case ' ':
            case "\t":
            case "\n":
            case "\r":
              if($token != '')
              {
                $tokens[] = $token;
                $token = '';
              }
              break;
            case '-':
              if($text{$i+1} == '-')
                $in_comment = true;
              else
                $token .= $text{$i};
              break;
            case '"';
              $in_quote = true;
              break;
            default:
              $token .= $text{$i};
          }
        }
      }
      if($token != '')
        $tokens[] = $token;
      return $tokens;
    }

   /**
    * Parse simple token
    *
    * @param array $tokens
    * @param integer $index
    * @param array $allowed
    * @return array
    */
    public function parse_simple_token($tokens, &$index, $allowed=NULL)
    {
      if(is_array($allowed))
      {
        if(in_array(strtolower($tokens[$index+1]), $allowed))
          return $tokens[++$index];
      }
      elseif(is_null($allowed))
      {
        if($tokens[$index+1] == '{')
          return $this->parse_bracket_token($tokens, ++$index, '{', '}');
        else
          return $tokens[++$index];
      }
      trigger_error("unknown token {$tokens[$index]} {$tokens[$index+1]}", E_USER_ERROR);
      return $tokens[++$index];
    }

   /**
    * Parse SYNTAX token
    *
    * @param array $tokens
    * @param integer $index
    * @return array
    */
    public function parse_SYNTAX_token($tokens, &$index)
    {
      $ret = NULL;
      switch($tokens[$index+1])
      {
        case 'SEQUENCE':
          if($tokens[$index+2] == 'OF')
          {
            $index += 2;
            if($tokens[$index+1] == '{')
              $ret = array('SEQUENCE OF'=>$this->parse_bracket_token($tokens, ++$index, '{', '}'));
            else
              $ret = array('SEQUENCE OF'=>$tokens[++$index]);
          }
          break;
        case 'OCTET':
          if($tokens[$index+2] == 'STRING')
          {
            $index += 2;
            if($tokens[$index+1] == '{')
              $ret = array('OCTET STRING'=>$this->parse_bracket_token($tokens, ++$index, '{', '}'));
            elseif($tokens[$index+1] == '(')
              $ret = array('OCTET STRING'=>$this->parse_bracket_token($tokens, ++$index, '(', ')'));
            else
              $ret = 'OCTET STRING';
          }
          break;
        case 'OBJECT':
          if($tokens[$index+2] == 'IDENTIFIER')
            $ret = $tokens[++$index] . ' ' . $tokens[++$index];
          else
            trigger_error("unknown token {$tokens[$index+1]} {$tokens[$index+2]}", E_USER_ERROR);
          break;
        case 'INTEGER':
        case 'Counter':
        case 'Counter32':
        case 'Counter64':
        case 'Integer32':
        case 'Gauge':
        case 'Gauge32':
        case 'TimeStamp':
        case 'TimeTicks':
        case 'PhysAddress':
        case 'IpAddress':
        case 'DateAndTime':
        case 'TimeInterval':
        case 'Unsigned32':
        case 'DisplayString':
          $ret = $tokens[++$index];
          if($tokens[$index+1] == '{')
            $ret = array($ret=>$this->parse_bracket_token($tokens, ++$index, '{', '}'));
          elseif($tokens[$index+1] == '(')
            $ret = array($ret=>$this->parse_bracket_token($tokens, ++$index, '(', ')'));
          break;
        default:
          $ret = $tokens[++$index];
          if($tokens[$index+1] == '{')
            $ret = array($ret=>$this->parse_bracket_token($tokens, ++$index, '{', '}'));
          elseif($tokens[$index+1] == '(')
            $ret = array($ret=>$this->parse_bracket_token($tokens, ++$index, '(', ')'));
          break;
      }
      return $ret;
    }

   /**
    * Parse bracket token
    *
    * @param array $tokens
    * @param integer $index
    * @param integer $start
    * @param integer $end
    * @return array
    */
    public function parse_bracket_token($tokens, &$index, $start, $end)
    {
      $begin = $index + 1;
      while($index + 1 < count($tokens) && $tokens[$index] != $end)
      {
        $index++;
        if($tokens[$index] == $start)
        {
          $this->parse_bracket_token($tokens, $index, $start, $end);
          $index++;
        }
      }
      return array_slice($tokens, $begin, $index - $begin);
    }
  }
?>
