rule Win_Trojan_W_180
{
strings:
	$a0 = { 1403f303cb51685254454e33d252ffd685c00f85cd0000008d85962040005053ffd66a406800100008 }

condition:
	$a0
}

        
