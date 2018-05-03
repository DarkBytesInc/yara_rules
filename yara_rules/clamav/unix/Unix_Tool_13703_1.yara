rule Unix_Tool_13703_1
{
strings:
	$a0 = { 31c031db31db31d231c9b03c31dbb30ecd80eb0b5b31c031c931d2b00bcd80e8f0ffffff2f62696e2f7368 }

condition:
	$a0
}

        
