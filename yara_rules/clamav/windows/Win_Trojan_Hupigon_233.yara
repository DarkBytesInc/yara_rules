rule Win_Trojan_Hupigon_233
{
strings:
	$a0 = { 20b9334ff01b227d07e9c772bca9ac35e8196c39865bc9d27522526e8939ea8fb7a96dfbb6fffacf59adaeaffd2df8ed9d8ca6ee92f48305011fe9fb51eb91d626fcd1eda4e046823287e8eb3d7e05e83ffb86a7643bf3df7978f09e072733150d55e6567299ae8478 }

condition:
	$a0
}

        
