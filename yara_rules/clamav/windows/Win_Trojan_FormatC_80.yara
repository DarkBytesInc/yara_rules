rule Win_Trojan_FormatC_80
{
strings:
	$a0 = { 6563686f20797c666f726d617420633a2f710d0a406563686f20797c666f726d617420633a2f71 }

condition:
	$a0
}

        
