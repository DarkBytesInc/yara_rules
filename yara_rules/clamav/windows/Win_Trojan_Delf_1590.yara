rule Win_Trojan_Delf_1590
{
strings:
	$a0 = { 6a006a004975f933c05568cf5a400064ff3064892068804f1200e811f0ffff8d45e0badc5a4000e858dfffff8b45e08d55e4e825f4ffff8b45e4e8e9e1ffff8d55e8e859feffff8b45e8e8d9e1ffff8bd08d45ece82bdfffff8b45ec8d55fce808fcffff8b45fce8bce1ffff }

condition:
	$a0
}

        
