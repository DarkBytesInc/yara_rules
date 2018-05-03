rule Html_Spyware_IMG_11
{
strings:
	$a0 = { 3c494652414d45[0-50]5352433d[0-200]3c2f494652414d453e }

condition:
	$a0
}

        
