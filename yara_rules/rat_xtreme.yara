/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Xtreme
{
      meta:
    description = "Xtreme RAT"
    author = "botherder https://github.com/botherder"
    severity = "7"
    type = "Malware"

    strings:
        $string1 = /(X)tremeKeylogger/ wide ascii
        $string2 = /(X)tremeRAT/ wide ascii
        $string3 = /(X)TREMEUPDATE/ wide ascii
        $string4 = /(S)TUBXTREMEINJECTED/ wide ascii

        $unit1 = /(U)nitConfigs/ wide ascii
        $unit2 = /(U)nitGetServer/ wide ascii
        $unit3 = /(U)nitKeylogger/ wide ascii
        $unit4 = /(U)nitCryptString/ wide ascii
        $unit5 = /(U)nitInstallServer/ wide ascii
        $unit6 = /(U)nitInjectServer/ wide ascii
        $unit7 = /(U)nitBinder/ wide ascii
        $unit8 = /(U)nitInjectProcess/ wide ascii

    condition:
        5 of them
}

rule xtreme_rat : Trojan
{
	  meta:
    author = "Kevin Falcoz"
    date = "23/02/2013"
    description = "Xtreme RAT"
    severity = "7"
    type = "Malware"
	
	strings:
		$signature1={58 00 54 00 52 00 45 00 4D 00 45} /*X.T.R.E.M.E*/
		
	condition:
		$signature1
}

rule XtremeRATCode : XtremeRAT Family 
{
      meta:
    description = "XtremeRAT code features"
    author = "Seth Hardy"
    last_modified = "2014-07-09"
    severity = "7"
    type = "Malware"
    
    strings:
        // call; fstp st
        $ = { E8 ?? ?? ?? ?? DD D8 }
        // hiding string
        $ = { C6 85 ?? ?? ?? ?? 4D C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 62 C6 85 ?? ?? ?? ?? 6D }
    
    condition:
        all of them
}

rule XtremeRATStrings : XtremeRAT Family
{
      meta:
    description = "XtremeRAT Identifying Strings"
    author = "Seth Hardy"
    last_modified = "2014-07-09"
    severity = "7"
    type = "Malware"
        
    strings:
        $ = "dqsaazere"
        $ = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32"
        
    condition:
       any of them
}

rule XtremeRAT : Family
{
      meta:
    description = "XtremeRAT"
    author = "Seth Hardy"
    last_modified = "2014-07-09"
    severity = "7"
    type = "Malware"
        
    condition:
        XtremeRATCode or XtremeRATStrings
}

rule xtremrat : rat
{
	  meta:
    author = "Jean-Philippe Teissier / @Jipe_"
    description = "Xtrem RAT v3.5"
    date = "2012-07-12"
    version = "1.0"
    filetype = "memory"
    severity = "7"
    type = "Malware"

	strings:
		$a = "XTREME" wide
		$b = "XTREMEBINDER" wide
		$c = "STARTSERVERBUFFER" wide
		$d = "SOFTWARE\\XtremeRAT" wide
		$e = "XTREMEUPDATE" wide
		$f = "XtremeKeylogger" wide
		$g = "myversion|3.5" wide
		$h = "xtreme rat" wide nocase
	condition:
		2 of them
}

rule xtreme_rat_0
{ 
	  meta:
    maltype = "Xtreme RAT"
    reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/xtreme-rat-targets-israeli-government/"
    description = "xtreme_rat_0"
    severity = "7"
    type = "Malware"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="5156"
		$data="windows\\system32\\sethc.exe"

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="AppData\\Local\\Temp\\Microsoft Word.exe"
	condition:
		all of them
}

rule xtreme_rat_1
{ 
	  meta:
    maltype = "Xtreme RAT"
    ref = "https://github.com/reed1713"
    reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/xtreme-rat-targets-israeli-government/"
    description = "xtreme_rat_1"
    severity = "7"
    type = "Malware"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="5156"
		$data="windows\\system32\\sethc.exe"

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="AppData\\Local\\Temp\\Microsoft Word.exe"
	condition:
		all of them
}
