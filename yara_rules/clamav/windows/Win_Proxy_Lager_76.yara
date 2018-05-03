rule Win_Proxy_Lager_76
{
strings:
	$a0 = { 1613270bc633906522fe0c1f6daf2c6bc1b32a09cec582f1cdafc2a35f2c1aeedd4b2f261d152208b6132776df2f286ea8ecf54aa39755b3dcf405fe99f22a112a78539e4601 }

condition:
	$a0
}

        
