rule Win_Trojan_Orchid_2
{
strings:
	$a0 = { 2201be03018bfeac3429aae2fac32020202020203b204d6f76652066696c6520706f696e74657220746f2073746172 }

condition:
	$a0
}

        
