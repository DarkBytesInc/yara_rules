rule Win_Trojan_Spambot_106
{
strings:
	$a0 = { 74724d9b2db918fc0ff0ff42e1910e8a8a58df3eaa5b951905b20200e427678dffff7f01cf293099eba299df623ce8543c344be39d57d71e3e39ffffffff3fd6e58d4e94ad0ee273fe84d2ff197a3c04ef791500c01f08732994ae179b98ffffffffbb5be735995824d583ea4c31 }

condition:
	$a0
}

        
