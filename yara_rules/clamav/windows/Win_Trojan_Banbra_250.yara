rule Win_Trojan_Banbra_250
{
strings:
	$a0 = { 6cbbb62fcfcfd22f77296b14482833410052a5b047c729ac9668dfe9c94321501f3facb901a5f02e0529b91facb622b8fa25b9a8525814791f168260c173dfd12da3b0ad8fdd3515aba521db5f53140505022fc95f3e80bfe6f4f4e9d4d4a910288045bda2521807d11fb4c02a546570b50a10b8f9a9312a10cae89b49daa850 }

condition:
	$a0
}

        