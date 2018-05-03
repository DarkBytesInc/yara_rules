rule Unix_Tool_13553_1
{
strings:
	$a0 = { eb1a5e31c08846078d1e895e0889460cb00b89f38d4e088d560ccd80e8e1ffffff2f62696e2f73684a414141414b4b4b4b }

condition:
	$a0
}

        
