rule Doc_Trojan_Bunny_2
{
strings:
	$a0 = { 53436f6465203d204469722822433a5c77696e646f77735c73797374656d5c62756e6e6965732e63706c2229 }
	$a1 = { 4d7367426f78202242756e6e69657321212121222c203438 }

condition:
	$a0 and $a1
}

        