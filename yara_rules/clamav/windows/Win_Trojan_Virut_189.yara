rule Win_Trojan_Virut_189
{
strings:
	$a0 = { e8??000000[0-100]8a03(f9|fc|66|eb|89|87|f8|f5|90)[0-15]8803c3 }

condition:
	$a0
}

        
