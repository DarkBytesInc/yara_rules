rule Win_Worm_Vesser_2
{
strings:
	$a0 = { b114defe1e96f69c9bc0c668f408d8afc1d5a130d55a9bace026e609b230404124c0852bb7b51abf3ec10a081bfa949b6ce5c8502205cb5ec1621415c9a1d1338885d3a53f35fa2dfcf19c2639d9cc7046447e4b1c375249f2b58e16b124bb1a0f009930b86e1b12617373207c08f7cdee0c0db1d0ca7e9fcc5ba7 }

condition:
	$a0
}

        