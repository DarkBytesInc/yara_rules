rule Win_Trojan_V_73
{
strings:
	$a0 = { 81ee0300501e062bc08ed8803eff0400754e0e1f8cc0488ec026803e00005a753f26a103002d800072365626a30300 }

condition:
	$a0
}

        
