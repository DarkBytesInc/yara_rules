rule Win_Trojan_Mybot_5481
{
strings:
	$a0 = { 3e18786f2743640d9c9889ca066ba7767c89617b5d4da33c5b349308bf9a905ed1cebc002e3fa9f795374a57d994e695447bbe0901acf91a52fa19dfa0f1fbee93da5421011e }

condition:
	$a0
}

        
