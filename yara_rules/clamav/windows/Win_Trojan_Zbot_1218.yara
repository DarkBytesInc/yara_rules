rule Win_Trojan_Zbot_1218
{
strings:
	$a0 = { 75596d2c754175545549555c757175447579754c756175747569757c75 }
	$a1 = { 35353507552b553d775c }
	$a2 = { 8874a148426f6d65 }

condition:
	$a0 and $a1 and $a2
}

        
