rule Win_Trojan_Xplog_1
{
strings:
	$a0 = { e81501008d0c1881f9000100007f208b3de41501008bcb03f88bc1c1e902f3a58bc883e103f3a4011de8150100eb1f8b3de41501008bc88bf133c0c1e902f3ab }

condition:
	$a0
}

        
