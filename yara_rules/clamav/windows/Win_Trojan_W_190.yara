rule Win_Trojan_W_190
{
strings:
	$a0 = { c3566963696f75732056697275732056657273696f6e20312e30558bec83ec20535657bf00 }

condition:
	$a0
}

        
