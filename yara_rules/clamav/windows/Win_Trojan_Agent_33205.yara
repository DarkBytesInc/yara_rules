rule Win_Trojan_Agent_33205
{
strings:
	$a0 = { 46a5b62d8f21719c594609166f9e79bbbf66c35d81b37a96f73b972b9dcee637b9973083cee64839dbd846f5e482dacf412480f467a34202a1904a983ea668bd0c15a390143200a60a8980f2a603cb4c1e38b80b4316fe4ad698a3ca62dfc2e77bfffffe877fbe7aff7dfef3efdf3ec8136607e3f3dfe0c18f53edbba5a93edec51789edcf6e84ae3ae43c62 }

condition:
	$a0
}

        