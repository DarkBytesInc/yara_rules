rule Win_Trojan_Spoofer_11
{
strings:
	$a0 = { 8b450c83c0088b105268a08c0408e8f5faffff83c408c745ec000000008d76008b450c83c00c8b1052e80afbffff83c40489c03945ec7208eb4d }
	$a1 = { 6f6f66696e67206174746163 }

condition:
	$a0 and $a1
}

        
