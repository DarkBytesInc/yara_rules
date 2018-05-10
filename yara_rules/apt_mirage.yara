/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule MirageStrings
{
      meta:
    description = "Mirage Identifying Strings"
    author = "Seth Hardy"
    last_modified = "2014-06-25"
    severity = "10"
    type = "Advanced Persistent Threat"
        
    strings:
        $ = "Neo,welcome to the desert of real." wide ascii
        $ = "/result?hl=en&id=%s"
        
    condition:
       any of them
}

rule Mirage
{
      meta:
    description = "Mirage"
    author = "Seth Hardy"
    last_modified = "2014-06-25"
    severity = "10"
    type = "Advanced Persistent Threat"
        
    condition:
        MirageStrings
}

rule Mirage_APT
{
      meta:
    Author = "Silas Cutler"
    Date = "yyyy/mm/dd"
    Description = "Malware related to APT campaign"
    Reference = "Useful link"
    description = "Mirage_APT"
    severity = "10"
    type = "Advanced Persistent Threat"
    
    strings:
        $a1 = "welcome to the desert of the real"
        $a2 = "Mirage"
        $b = "Encoding: gzip"
        $c = /\/[A-Za-z]*\?hl=en/

    condition: 
        (($a1 or $a2) or $b) and $c
}

