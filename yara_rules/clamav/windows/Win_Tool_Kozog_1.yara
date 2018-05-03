rule Win_Tool_Kozog_1
{
strings:
	$a0 = { 538bd8a1b040400089038bd3b8dc3a4000e8c2ffffff84c05bc300006b6f7a69726f672e6e657469737361742e6e6574 }

condition:
	$a0
}

        
