rule Win_Trojan_Bancos_980
{
strings:
	$a0 = { 39dba27fe2e01d886c625c6021480cc990d8a576b9155a593dacd390f26aa2fd47d55a7ffda6689a0585efea1ab87e4c8189696d03ac0da9331bf3a6f9cb2e55c12c8813c4149589efb6498b4dd7430975ff7ab1c447c9a3 }

condition:
	$a0
}

        
