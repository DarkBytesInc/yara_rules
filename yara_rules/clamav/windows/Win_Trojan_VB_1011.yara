rule Win_Trojan_VB_1011
{
strings:
	$a0 = { 54686520476f6473204f66204465737472756374696f6e }
	$a1 = { 6d0061006e00670061005f006d0061006e }

condition:
	$a0 and $a1
}

        
