rule Win_Trojan_Hupigon_1628
{
strings:
	$a0 = { b676f669d6d3ef2185490eed834ecf91acac78656aa546bc347ee7a38e13c8d5e96aee645aacfbc410a85246fef772cd81cc0f1b36fc932dae92239cc7cf03424edf9b7d97682cd44c63eff7487c0b4fde0d89ef5abac03a4be76383c7d86f1767dc7a9a98797329c0cb8cbe6590 }

condition:
	$a0
}

        
