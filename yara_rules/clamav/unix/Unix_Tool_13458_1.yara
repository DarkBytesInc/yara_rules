rule Unix_Tool_13458_1
{
strings:
	$a0 = { 31c031db31c9b046cd80eb1d5e88460789460c89760889f38d4e088d560cb00bcd8031c0 }

condition:
	$a0
}

        
