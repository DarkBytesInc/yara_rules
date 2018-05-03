rule Html_Spyware_IMG_9
{
strings:
	$a0 = { 3c494652414d45207372633d[0-200]3c2f696672616d653e }

condition:
	$a0
}

        
