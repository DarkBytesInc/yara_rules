rule Win_Trojan_W_56
{
strings:
	$a0 = { b5aa0a4400e80103000081bde20a4400504500000f85a60100006681bd2e0b44000df00f849701 }

condition:
	$a0
}

        
