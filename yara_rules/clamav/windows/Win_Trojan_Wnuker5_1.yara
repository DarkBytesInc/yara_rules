rule Win_Trojan_Wnuker5_1
{
strings:
	$a0 = { 6b653520206265746120310a466f6e742e436f6c6f72070c636c57696e646f77546578740b466f6e742e48656967687402f509466f6e742e4e616d65060d4d532053616e732053657269660a466f6e742e5374796c650b000d506978656c73506572496e636802600a5465 }

condition:
	$a0
}

        