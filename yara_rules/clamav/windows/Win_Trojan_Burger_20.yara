rule Win_Trojan_Burger_20
{
strings:
	$a0 = { 90b8000026a3a80226a3aa0226a2ac02b419cd212ea2ff02b4478ae48bf6b60004018ad2908ad08ad290be0103cd21b40eb200cd21b0013c017502b006b4 }

condition:
	$a0
}

        
