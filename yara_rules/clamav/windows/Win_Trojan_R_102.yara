rule Win_Trojan_R_102
{
strings:
	$a0 = { eb01906800080768c0071f[0-6]b90002be00[0-16]fcf3a4cb00000000000000000000000000000000[0-4]8cc88ed88ec0 }

condition:
	$a0
}

        
