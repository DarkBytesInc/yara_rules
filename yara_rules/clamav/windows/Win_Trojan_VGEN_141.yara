rule Win_Trojan_VGEN_141
{
strings:
	$a0 = { be000190e806050bc090740b5690e86b025ee8b7041e072e80bcd80201742790be43018b3ec90381c7ca0657b90500 }

condition:
	$a0
}

        
