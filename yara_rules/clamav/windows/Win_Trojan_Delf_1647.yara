rule Win_Trojan_Delf_1647
{
strings:
	$a0 = { b89c474000ba95464000b900010000e845f2ffff8d45e4508d55e0b8ac2d4000e878fcffff8b4de0bac02d4000a19c474000e892fdffff8b55e4b89c474000e839f1ffff8d45dc508d55d8b8ac2d4000e848fcffff }

condition:
	$a0
}

        
