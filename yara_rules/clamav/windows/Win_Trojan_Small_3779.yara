rule Win_Trojan_Small_3779
{
strings:
	$a0 = { d57f318821d736c8537089ec6434e69c0f4ccaf5794dc9fb6da9cc5f64d75dee609fc7f39ac9791f74547127568874631e03baa29415fbe90bcbb029bf54729c0fd7b7989a5aa46e1213abf11bc0 }

condition:
	$a0
}

        
