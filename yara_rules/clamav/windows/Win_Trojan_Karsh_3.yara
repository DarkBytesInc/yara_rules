rule Win_Trojan_Karsh_3
{
strings:
	$a0 = { 0c00000073007400610072007400200000000000520065006300650069007600650064005f00460069006c00650000000a00000043003a005c003a00310000000e0000002a002e0073006800610072006b000000530065006e0074005f00460069006c00650000005400000030001b00fc00f800e600b200a300ac207a0062003c00320026000100e500cd00ba00aa007e0072005a00 }

condition:
	$a0
}

        