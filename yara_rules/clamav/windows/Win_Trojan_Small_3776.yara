rule Win_Trojan_Small_3776
{
strings:
	$a0 = { 66643e90a9b41cd316601d1f6e655d5107b88162cb14320de3f88a77e4f7906b40fbf4626e8c835e36f6889860a8b472eb9fbc541fa3f81c9ae83792ac297f0962dfbebdeba0310d6ee62d98f1d2 }

condition:
	$a0
}

        
