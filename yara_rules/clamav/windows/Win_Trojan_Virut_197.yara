rule Win_Trojan_Virut_197
{
strings:
	$a0 = { e800000000558b6c2404816c2404????????e8??0100008bc8e8??0100002bc13d000100000f83??0000008b5c240881e300f0ffff81ed05104000 }

condition:
	$a0
}

        
