rule Win_Trojan_VB_1041
{
strings:
	$a0 = { 68e8114000e8f0ffffff00000000000030 }
	$a1 = { 3342414637423546334543364342354238 }
	$a2 = { 4240533834453834454240537b }

condition:
	$a0 and $a1 and $a2
}

        
