rule Win_Trojan_Small_3440
{
strings:
	$a0 = { a2a1af4fa943a54f7657216aeb1e6f2343df5f723e6c14c2bb8dd2cf7e91543971539994b211827308b0e2ea0cf749daf93543271060ab148444dab8de8d7541 }

condition:
	$a0
}

        
