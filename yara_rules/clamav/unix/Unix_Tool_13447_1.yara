rule Unix_Tool_13447_1
{
strings:
	$a0 = { 29c0b04729dbb30c89d9cd80eb185e29c088460789460c897608b00b87f38d4b088d530ccd80e8e3ffffff2f62696e2f7368 }

condition:
	$a0
}

        
