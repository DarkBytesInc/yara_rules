rule Unix_Tool_13728_1
{
strings:
	$a0 = { eb1931c0b01731dbcd8031c0b02e31dbcd8031c0b00b5b89d1cd80e8e2ffffff2f62696e2f7368 }

condition:
	$a0
}

        
