rule Win_Trojan_Peed_145
{
strings:
	$a0 = { e8330000005589e5890189d88b5d086bdb0343c9c2040089daf7da01d0ba2200000083f8000f849c000000c3f7db29df }

condition:
	$a0
}

        
