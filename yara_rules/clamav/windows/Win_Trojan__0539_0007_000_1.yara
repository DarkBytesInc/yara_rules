rule Win_Trojan__0539_0007_000_1
{
strings:
	$a0 = { 02ba03010316060183ea032bcab440cd217214909090b80057cd21720a909090b80157b11d }

condition:
	$a0
}

        
