rule Win_Trojan_Packed_161
{
strings:
	$a0 = { 5589e581c404f9ffff535657c745e8b8280000c745e4010000008b45e440508b45e85a89d199f7f90faf45e88945e831c08945e0 }

condition:
	$a0
}

        
