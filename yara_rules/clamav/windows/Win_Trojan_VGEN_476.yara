rule Win_Trojan_VGEN_476
{
strings:
	$a0 = { 20b801028d1e3f01b90120ba8020cd137210c687ff0120b80103cd138d16030173048d162401b409cd21cd201a }

condition:
	$a0
}

        
