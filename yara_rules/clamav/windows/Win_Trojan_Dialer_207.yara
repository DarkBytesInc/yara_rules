rule Win_Trojan_Dialer_207
{
strings:
	$a0 = { 412d4338453037384137463736327d270d0a097d0d0a0953797357656254656c65636f6d2e53 }

condition:
	$a0
}

        
