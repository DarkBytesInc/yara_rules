rule Win_Trojan_Burger_18
{
strings:
	$a0 = { 909090b8000026a3a80226a3aa0226a2ac02b419cd212ea2b702b447b600b0018ad0beb902cd21b40eb200cd21b0013c017502b006b400bba00203d883c3012e }

condition:
	$a0
}

        
