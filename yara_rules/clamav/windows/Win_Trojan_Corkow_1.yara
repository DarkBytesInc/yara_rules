rule Win_Trojan_Corkow_1
{
strings:
	$a0 = { 500065007200740020004c0061006f00730020004a00650072006b000000 }

condition:
	$a0
}

        
