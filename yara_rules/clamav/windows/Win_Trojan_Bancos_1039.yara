rule Win_Trojan_Bancos_1039
{
strings:
	$a0 = { f07fad593b2be65afe86bf335f6b81537edbce5bd43eaaf9b1aeeb3d0cac49ec0b11b88303bec6bff7047d1e33b9fff4f463505be1c123781aa54aa0c49aa8ee8be9f5cfe56f25c2708a081b60ac964290cb024e82f1946a }

condition:
	$a0
}

        
