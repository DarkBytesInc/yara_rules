rule Win_Worm_Hybris_5
{
strings:
	$a0 = { 120000ba00104000812a7078392c81c2040000004d75f16800104000c300000000 }

condition:
	$a0
}

        
