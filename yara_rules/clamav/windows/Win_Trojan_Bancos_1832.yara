rule Win_Trojan_Bancos_1832
{
strings:
	$a0 = { 27ca1ba52f6b928672025c417f208860057a542aae9b2d09d1f6d1512abb9f563ffb89131b990e994fb525dddfd13ba37837f7f025577e89a4555e9c55ee377c80a16e3d90db }

condition:
	$a0
}

        
