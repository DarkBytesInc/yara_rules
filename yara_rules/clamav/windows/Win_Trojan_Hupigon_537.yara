rule Win_Trojan_Hupigon_537
{
strings:
	$a0 = { 475e907cfa1fba02159658059617cf754cea567205818c68e3b3ab2793b22aa2e302b2c7b7e951fc97b43aa457f03a6a952026cce0a027bd2cce08f0beb07c56ba3e1e03d80e494b9dbc481255e4 }

condition:
	$a0
}

        
