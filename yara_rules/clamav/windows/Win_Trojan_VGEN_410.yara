rule Win_Trojan_VGEN_410
{
strings:
	$a0 = { 90e80000582d05019533c0b41a8d968202cd218db682038dbe8a03b90500f3a4b419cd213c027403e99302b44732d2 }

condition:
	$a0
}

        
