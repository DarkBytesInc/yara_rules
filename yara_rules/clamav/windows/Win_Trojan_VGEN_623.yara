rule Win_Trojan_VGEN_623
{
strings:
	$a0 = { 2020b801028d1e4301b90120ba8020cd137210c687ff01aab80103cd138d16030173048d162601b409cd21cd201a }

condition:
	$a0
}

        
