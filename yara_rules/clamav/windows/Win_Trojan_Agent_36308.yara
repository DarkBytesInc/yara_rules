rule Win_Trojan_Agent_36308
{
strings:
	$a0 = { 653d2828222229292e7375627374723b633d22766172205f6c313d2734633230366635373833656239643b706e77617928297574696f7b2e76737367272c68266c743b2b697d2a2f646b7225782d775b5d6d636a5e3f3a6c626b7179657571666d223b653d6528295b226576616c225d3b733d22223b696628243d3d3d74686973297b613d22636f6e636174223b }

condition:
	$a0
}

        