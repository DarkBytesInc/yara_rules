rule Win_Trojan_Dialer_157
{
strings:
	$a0 = { 452b1b1d61b3ff9b649000215355424c4f47494e1f00bf32730b2d736c0068747470dd7afbff3a2f2f36362e3233302e31353103 }

condition:
	$a0
}

        
