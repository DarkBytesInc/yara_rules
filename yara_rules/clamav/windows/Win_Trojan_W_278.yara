rule Win_Trojan_W_278
{
strings:
	$a0 = { 60e8000000005f81ef063040008db721304000b954020000668136fb2d4646e2f7 }

condition:
	$a0
}

        
