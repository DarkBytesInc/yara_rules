rule Win_Trojan_Lineage_323
{
strings:
	$a0 = { cccf6dc4aa771ef567f2a873d4fb37f7896d271f331bffc5a23cb2d247b44e640642c5b67470088853ed55bfacbad7328d4e02ed4043cae8119bcb095c667e268caf53737aeeb1aaa54652fe4bd83be0f2ebec912c4624d061c31e170eabb0 }

condition:
	$a0
}

        
