rule Win_Trojan_Delf_2305
{
strings:
	$a0 = { 6a008b45fce884affeff508d95f4feffff33c0e8ee8cfeff8b85f4feffffe86baffeff50e805c9feff68d49c410068e09c410068fc9c410068049d4100e8b4cafeffb8149d4100e86efeffff84c075076a00e83fc9feff33c0 }

condition:
	$a0
}

        
