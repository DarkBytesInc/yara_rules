rule Win_Trojan_Virut_219
{
strings:
	$a0 = { 433a5c31642e747874[0-15]6d736d7367732e657865[0-28]5c43757272656e7456657273696f6e5c52756e }

condition:
	$a0
}

        
