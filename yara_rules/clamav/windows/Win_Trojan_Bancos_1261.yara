rule Win_Trojan_Bancos_1261
{
strings:
	$a0 = { 8e3e0cebfbeeb3dd2e7993ca077a8d7fb58bec0e5a4f59f857c6c9bb8e1cb95171dd89290f4d5c349cde978326683a0233dd66a7811786ebca3f3a121f4b40ac6b69413f1ea53e64556ede3122bd28e6c421cfa97ea167e5d06a1e2faa3a8ac5b96c67c8941af548044d79335699e38d58c1bbdba746c06b7a7061a55b886f34b9c864 }

condition:
	$a0
}

        