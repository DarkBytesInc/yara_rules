rule Win_Trojan_Virut_56
{
strings:
	$a0 = { e8??000000[0-50]8603(f9|fc|66|eb|89|87|f8|f5|90)[0-15]8803[0-50]ffe2 }

condition:
	$a0
}

        
