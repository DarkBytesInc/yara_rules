rule Win_Trojan_Zorg_1
{
strings:
	$a0 = { ffb53cf9ffff68a43d41008d9538f9ffffb806000000e82aecfeffffb538f9ffff8d8550f9ffffba0b000000e82807ffff8b8550f9ffffe85d08ffff508d9534f9ffff33c0e8fbebfeff8d8534f9ffffba943d4100e84706ffff8b8534f9ffffe83408ffff506a006a01e8eaf4ffff }

condition:
	$a0
}

        
