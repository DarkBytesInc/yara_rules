rule Win_Trojan_N_16
{
strings:
	$a0 = { 5d81ed03001e06b81174cd2181fb56527453b44abbffffcd2183eb2690b44acd21b448bb2500cd21723b488ec026c60600005a26c70601000800400e1f }

condition:
	$a0
}

        
