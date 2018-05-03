rule Unix_Tool_13743_1
{
strings:
	$a0 = { eb1f31c0b0b65b31c931d2cd8031c0b00f89db66b9ed09cd8031c0b00131dbcd80e8dcffffff2f62696e2f7368 }

condition:
	$a0
}

        
