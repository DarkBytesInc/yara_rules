rule Win_Trojan_Virut_374
{
strings:
	$a0 = { e8??000000[0-100]8606(f9|fc|66|eb|89|87|f8|f5|90)[0-15]8806[0-3]c3 }

condition:
	$a0
}

        
