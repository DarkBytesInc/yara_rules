rule Win_Trojan_SillyC_30
{
strings:
	$a0 = { 8b2e7b01be00ffba00feb41acd21b42acd2180fa177505eaf0ff00f0ba75012bc9b44ecd21b17dba1efeb8023dcd21938bd6b43fcd2157a75f7417b002e82600a37b01b440cd212ac0e81a008bd7b440cd21b43ecd21b6feb44fcd21 }

condition:
	$a0
}

        
