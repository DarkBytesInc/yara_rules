rule Win_Trojan_Dyfuca_13
{
strings:
	$a0 = { 6990887c704459465543415f5349a2240773310b454e076cf6df5b5054494d495a4552220f454ed4f376 }

condition:
	$a0
}

        
