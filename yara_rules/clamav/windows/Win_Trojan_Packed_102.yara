rule Win_Trojan_Packed_102
{
strings:
	$a0 = { 719f51590897515949e02b2171ef51591118499f274f07df278e071f27ce075f270e079e274e07de49e02951278d071e }

condition:
	$a0
}

        
