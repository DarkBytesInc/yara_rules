rule Unix_Tool_13670_1
{
strings:
	$a0 = { eb0b5b31c031c931d2b00bcd80e8f0ffffff2f62696e2f7368 }

condition:
	$a0
}

        
