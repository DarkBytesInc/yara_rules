rule Win_Trojan_Bancos_110
{
strings:
	$a0 = { 504e45542f6772616367692e65786500736d736269742e6578650000538bd833d28b8350030000e81903201ca11cdd4800e8190571e0ba1c020000a11cdd4800e81903a0f0bae4020000a11cdd4800e81903a0ccb2048bc3e819054cf85bc390558bec6a0053568bf18bd833c05568f86e480064ff306489 }

condition:
	$a0
}

        