rule Win_Spyware_Goldun_135
{
strings:
	$a0 = { d916f8d4fcd8d000e038e4c311613f0400bf63f4d9dcaf1c9b071b2582082b7086fdbfac0fbd2a8bce40c8394df00f0083661b8780690320e4deea0517e33773009c0febca04170022cc50 }

condition:
	$a0
}

        
