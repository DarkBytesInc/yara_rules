rule Win_Trojan_Worf_3
{
strings:
	$a0 = { 7020283f292054726f6a616e20486f72736520576f72662076322e30210d0a5b4642695d }

condition:
	$a0
}

        
