rule Win_Trojan_Vundo_311
{
strings:
	$a0 = { fe1e399550cf9be6ebcfeceeed3815c852210af0cc2b527828eba6f2fa36c7a7c8e8ba0a028744559a22f7558431f2e31ef9ba3c1e94603b17bf882f5758504c4fbb52e9cca36f3a7dc76c3d1ca54c746881d3ce3d3a165e62344f50e9a901c90c195be2594bd3731aaa96aa3ce21b4cd3446b4265af8145178c54f4ac7de6add3f3ee47c554b570378cd2b0 }

condition:
	$a0
}

        