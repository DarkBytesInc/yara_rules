rule Win_Trojan_Delf_1531
{
strings:
	$a0 = { 68a8610000e87d27ffffb201a1487a4100e86de0ffffa3a8ca4100ba02000080a1a8ca4100e8f9e0ffffbaa8a64100a1a8ca4100e8cee8ffff84c00f84d3000000baa8a64100a1a8ca4100e85fe2ffff8d4dd4bad0a64100a1a8ca4100e8a9e6ffff }

condition:
	$a0
}

        
