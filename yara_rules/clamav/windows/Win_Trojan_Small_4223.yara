rule Win_Trojan_Small_4223
{
strings:
	$a0 = { c45433c0648f00586819454000c368194540008b4424108f80b800000033c0c3433a5c }

condition:
	$a0
}

        
