rule Win_Trojan_Aref_1
{
strings:
	$a0 = { cd210ae474591e8cd8488ed88a160000c60600004d8b1e030083eb26891e030003c3408ec0268816000026c60601 }

condition:
	$a0
}

        
