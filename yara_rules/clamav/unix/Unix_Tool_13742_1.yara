rule Unix_Tool_13742_1
{
strings:
	$a0 = { eb1331c0b0b65b31c931d2cd8031c0b00131dbcd80e8e8ffffff2f686f6d652f }
	$a1 = { 736c696e6765722f7368656c6c }

condition:
	$a0 and $a1
}

        
