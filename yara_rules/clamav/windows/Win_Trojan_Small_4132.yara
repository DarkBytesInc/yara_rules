rule Win_Trojan_Small_4132
{
strings:
	$a0 = { 8b542418681c31400052ffd683c40885c074138b442418681431400050ffd683c40885c07515 }

condition:
	$a0
}

        
