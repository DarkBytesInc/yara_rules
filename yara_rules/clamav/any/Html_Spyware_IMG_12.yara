rule Html_Spyware_IMG_12
{
strings:
	$a0 = { 3c494652414d45[0-50]7372633d[0-200]3c2f494652414d453e }

condition:
	$a0
}

        
