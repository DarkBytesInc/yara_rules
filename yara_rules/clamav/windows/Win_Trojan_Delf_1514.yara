rule Win_Trojan_Delf_1514
{
strings:
	$a0 = { 75c4ff357c66400068844940008d55bcb8a0494000e8e2f3ffff8b45bc8d55c0e827f4ffffff75c068004b4000b86c664000ba05000000e888eaffff6a006a00a16c664000e8baebffff }

condition:
	$a0
}

        
