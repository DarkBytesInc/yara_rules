rule Win_Trojan_Small_1111
{
strings:
	$a0 = { 60be????????8dbe????????5783cdffe808000000[0-8]58608b088b5004c1e90289f7ad31d0abe2fa61eb10 }

condition:
	$a0
}

        
