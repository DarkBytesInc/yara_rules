
rule Ping_Command_in_EXE {
     meta:
    description = "Detects an suspicious ping command execution in an executable"
    author = "Florian Roth"
    reference = "Internal Research"
    date = "2016-11-03"
    score = 60
    severity = "5"
    type = "Unknown"
   strings:
      $x1 = "cmd /c ping 127.0.0.1 -n " ascii
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule GoogleBot_UserAgent {
     meta:
    description = "Detects the GoogleBot UserAgent String in an Executable"
    author = "Florian Roth"
    reference = "Internal Research"
    date = "2017-01-27"
    score = 65
    severity = "5"
    type = "Unknown"
   strings:
      $x1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii

      $fp1 = "McAfee, Inc." wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and $x1 and not 1 of ($fp*) )
}

rule Gen_Net_LocalGroup_Administrators_Add_Command {
     meta:
    description = "Detects an executable that contains a command to add a user account to the local administrators group"
    author = "Florian Roth"
    reference = "Internal Research"
    date = "2017-07-08"
    severity = "7"
    type = "Malware"
   strings:
      $x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule Suspicious_Script_Running_from_HTTP {
     meta:
    description = "Detects a suspicious "
    author = "Florian Roth"
    score = 50
    date = "2017-08-20"
    severity = "5"
    type = "Unknown"
   strings:
      $s1 = "cmd /C script:http://" ascii nocase
      $s2 = "cmd /C script:https://" ascii nocase
      $s3 = "cmd.exe /C script:http://" ascii nocase
      $s4 = "cmd.exe /C script:https://" ascii nocase
   condition:
      1 of them
}

rule ReconCommands_in_File {
     meta:
    description = "Detects various recon commands in a single file"
    author = "Florian Roth"
    reference = "https://twitter.com/haroonmeer/status/939099379834658817"
    date = "2017-12-11"
    score = 40
    severity = "5"
    type = "Unknown"
   strings:
      $ = "tasklist"
      $ = "net time"
      $ = "systeminfo"
      $ = "whoami"
      $ = "nbtstat"
      $ = "net start"
      $ = "qprocess"
      $ = "nslookup"
   condition:
      filesize < 5KB and 4 of them
}

rule VBS_dropper_script_Dec17_1 {
     meta:
    description = "Detects a supicious VBS script that drops an executable"
    author = "Florian Roth"
    reference = "Internal Research"
    date = "2018-01-01"
    score = 80
    severity = "5"
    type = "Unknown"
   strings:
      $s1 = "TVpTAQEAAAAEAA" // 14 samples in goodware archive
      $s2 = "TVoAAAAAAAAAAA" // 26 samples in goodware archive
      $s3 = "TVqAAAEAAAAEAB" // 75 samples in goodware archive
      $s4 = "TVpQAAIAAAAEAA" // 168 samples in goodware archive
      $s5 = "TVqQAAMAAAAEAA" // 28,529 samples in goodware archive

      $a1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
   condition:
      filesize < 600KB and $a1 and 1 of ($s*)
}

rule SUSP_PDB_Strings_Keylogger_Backdoor {
     meta:
    description = "Detects PDB strings used in backdoors or keyloggers"
    author = "Florian Roth"
    reference = "Internal Research"
    date = "2018-03-23"
    severity = "5"
    type = "Unknown"
   strings:
      $ = "\\Release\\PrivilegeEscalation"
      $ = "\\Release\\KeyLogger"
      $ = "\\Debug\\PrivilegeEscalation"
      $ = "\\Debug\\KeyLogger"
      $ = "Backdoor\\KeyLogger_"
      $ = "\\ShellCode\\Debug\\"
      $ = "\\ShellCode\\Release\\"
      $ = "\\New Backdoor"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB
      and 1 of them
}
