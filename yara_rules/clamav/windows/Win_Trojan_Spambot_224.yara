rule Win_Trojan_Spambot_224
{
strings:
	$a0 = { 6cd8358b821f5f9b146bab2bbe181a72af52155abb2484acdbffffffffe53b32aeef5c3b6d41f943e0fc8ecf30165345d4b634e61e43b32a33690f2167fcffffffe51fad55971b949a9230b7a0eed6b6f6bd5206982b125f0a4abd1aff374affffff03b92e096065eeca2c5930ea }

condition:
	$a0
}

        
