rule Win_Trojan_Uruguay_1
{
strings:
	$a0 = { 83c60e15df010104464603f90c3ba02e7519a02e75199d2f7519770399096e5809e80702222d2d0740fe2199 }

condition:
	$a0
}

        
