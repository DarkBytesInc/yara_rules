rule Win_Trojan_Starter_7
{
strings:
	$a0 = { 60e800000000b878000000010424e808000000ffd061e9????feff33c06403403078088b400c8b701cad8b4008eb098b40348d407c8b403c95bf8e4e0eec8b753c8b74357803f5568b762003f533c94941ad33db360fbe142838f27408c1cb0d03da40ebef3bdf75e75e8b5e2403dd66 }

condition:
	$a0
}

        