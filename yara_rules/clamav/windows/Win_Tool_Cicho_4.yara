rule Win_Tool_Cicho_4
{
strings:
	$a0 = { e81e0000008b6424086a00680020400068252040006a00e8e6ef00006a00e8df }

condition:
	$a0
}

        
