rule Win_Trojan_Leprosy_17
{
strings:
	$a0 = { f6e84d000bc07406e8140046eb08ba6302b43bcd214683fe037ce6eb005ec38b165e0283c21e33c9b001b443cd21a15e02051e0050e80601598b1e7202b9 }

condition:
	$a0
}

        
