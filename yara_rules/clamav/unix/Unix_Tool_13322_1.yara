rule Unix_Tool_13322_1
{
strings:
	$a0 = { eb0b5bb00acd80b00131dbcd80e8f0ffffff }

condition:
	$a0
}

        
