rule Win_Trojan_Bancos_887
{
strings:
	$a0 = { 0e9af167a0a129659aefbdb7d7b0ea499b8f7b3d10c08705929b26e7d04092d7c1114c1e01b209d2182dff0bc34b30ac9b035ed05c26106e8c629979748d80078eb2b5b979da }

condition:
	$a0
}

        
