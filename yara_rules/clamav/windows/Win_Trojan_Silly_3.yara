rule Win_Trojan_Silly_3
{
strings:
	$a0 = { 7479206e756c0d0a3a446f740d0a666f722025256220696e2028254e4557252a2e6261742920646f20636f7079202530202525620d0a736574204e45573d2e2e5c254e4557250d0a636f707920253020254e45572525300d0a6966206e6f7420657869737420254e455725253020 }

condition:
	$a0
}

        