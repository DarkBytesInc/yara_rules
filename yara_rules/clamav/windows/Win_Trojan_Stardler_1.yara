rule Win_Trojan_Stardler_1
{
strings:
	$a0 = { 25735c25732e65786500000065786300687474703a2f2f3139332e3135392e3138332e3133382f2573 }

condition:
	$a0
}

        