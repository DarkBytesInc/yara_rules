rule Win_Trojan_SixFaces_1
{
strings:
	$a0 = { 909090902000413a5c5456312e434f4d004d002e434f4d000000000000002a2e636f6d000000e9f1010d2c1c6b28 }

condition:
	$a0
}

        
