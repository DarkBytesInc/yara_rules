rule Win_Trojan_W_181
{
strings:
	$a0 = { 03f303cb51685254454e33d252ffd685c00f85cd0000008d85992040005053ffd66a406800100008 }

condition:
	$a0
}

        
