rule Win_Trojan_SdBot_1924
{
strings:
	$a0 = { b186bcff398ba91c267df49a6f4dc7f6ceee23e8be39c43b8428bb145733da771eba1e2ad82e3262552b2a18e2359e73f004ce8f342954c57072daa0210e58c679c23cbc1c4bc3a591fe6f13acf563c536c54fd63f1dfc9c6359 }

condition:
	$a0
}

        
