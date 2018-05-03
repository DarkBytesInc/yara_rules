rule Unix_Tool_18885_1
{
strings:
	$a0 = { eb195bb800000000884309895b0a89430eb00b8d4b0a8d530ecd80e8e2ffffff2f62696e2f64617368 }

condition:
	$a0
}

        
