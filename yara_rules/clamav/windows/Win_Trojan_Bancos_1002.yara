rule Win_Trojan_Bancos_1002
{
strings:
	$a0 = { 90aa80108fb4235ef32a248380cbdf7089c6280bfaeebddafa5623b7cbbbf74c47233de30dd61866eb0c62a5b7750932a3959c0be8d4f330ca3d76f9f10e8366341d7721311556f0d680becc3bc0bcd1152b }

condition:
	$a0
}

        
