rule Win_Trojan_Virut_62
{
strings:
	$a0 = { e8??000000[0-50]8606(f9|fc|66|eb|89|87|f8|f5|90)[0-15]8606[0-50]ffe3 }

condition:
	$a0
}

        