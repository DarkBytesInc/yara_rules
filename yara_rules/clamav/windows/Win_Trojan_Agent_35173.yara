rule Win_Trojan_Agent_35173
{
strings:
	$a0 = { 9cf7d1e8000000005f7500fcfd8bd7c1c18d81ef22100100f85784c4c1e00581c23c000000fd40906800000000 }

condition:
	$a0
}

        
