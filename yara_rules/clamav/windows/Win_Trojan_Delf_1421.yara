rule Win_Trojan_Delf_1421
{
strings:
	$a0 = { 64ff306489206a0a682c840010a160a6001050e840c3ffff8bd853a160a6001050e8cac3ffff8bf853a160a6001050e894c3ffff8bf056e894c3ffff8bd885db7426 }

condition:
	$a0
}

        
