rule Win_Trojan_Faerie_3
{
strings:
	$a0 = { 1304e811008db62702bf0001a551e8050059a4eb0c90b9000043904b4149e2f9c3b41a8d966002cd21b902008d9621 }

condition:
	$a0
}

        
