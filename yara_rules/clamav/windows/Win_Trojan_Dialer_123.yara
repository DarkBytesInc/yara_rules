rule Win_Trojan_Dialer_123
{
strings:
	$a0 = { 24a10aeb2a18158170039a93cba66414a954a028b0ff6fdb2042010000232032392c39352080ff77ffff2f45696e7761 }

condition:
	$a0
}

        
