rule Win_Trojan_Mvix_1
{
strings:
	$a0 = { 0900008d46d416509a8c0900008d46d41650666a00666a019a740900000bc075d84681fe0004 }

condition:
	$a0
}

        
