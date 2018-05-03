rule Win_Worm_Mydoom_3
{
strings:
	$a0 = { 515549548e07fd686cb82e0cc6626aeb3a20484da3ed36106f21272a3335ebb441e2ff657c403235ef43505420544f3a3c7e7a36eed93e26134c67524f4de9e8 }

condition:
	$a0
}

        
