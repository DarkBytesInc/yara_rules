rule Win_Trojan_VGEN_648
{
strings:
	$a0 = { e800005d81ed07010e16585b3bc3754d565668008d0733db8db6040133ffe80a000e078db659015fa5a5c3b80102b901 }

condition:
	$a0
}

        
