rule Win_Trojan_Vgen_148
{
strings:
	$a0 = { d09c4c27a804039d1225a9a413e900e7be000156b95f02c704fa52c6440217813413244646e2f831f631c9c300 }

condition:
	$a0
}

        
