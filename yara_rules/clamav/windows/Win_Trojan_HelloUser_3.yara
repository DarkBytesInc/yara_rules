rule Win_Trojan_HelloUser_3
{
strings:
	$a0 = { e800005d81ed09018db62501568b962301b95a018bfeac32c2aae2fac336908e37cc8c736ffb20822c8c52ccfb17bb80a2378936378f3536cac592822ffb17beb0493482388434 }

condition:
	$a0
}

        
