rule Win_Trojan_Phrostic_2
{
strings:
	$a0 = { 703a2f2f7068726f737469632e6d696e652e6e752f7365727665722e6578650000000000000000000000000000000000433a5c50726f6772616d2046696c65735c556e696e7374616c6c20496e666f726d6174696f6e5c72656d6f76652e657865000000000000000000000000 }

condition:
	$a0
}

        