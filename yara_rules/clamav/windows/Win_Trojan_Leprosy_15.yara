rule Win_Trojan_Leprosy_15
{
strings:
	$a0 = { f6e851000bc0740ae8180046fe063702eb08ba3802b43bcd214683fe037ce2eb005ec38b16320283c21e33c9b001b443cd21a13202051e0050e8d500598b }

condition:
	$a0
}

        
