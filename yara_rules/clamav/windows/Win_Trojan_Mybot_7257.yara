rule Win_Trojan_Mybot_7257
{
strings:
	$a0 = { 12daf64ce9afa80ce73238b7b78518d5faf1f122e01ff91d0b2bc6e3c7b572143054edbe2ea595dc6e67440e147ad99860666277a445fb87b01a4d87809771f0dd5db3006362d2f1a00959bd590e }

condition:
	$a0
}

        
