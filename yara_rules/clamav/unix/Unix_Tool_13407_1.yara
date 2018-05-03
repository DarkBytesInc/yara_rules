rule Unix_Tool_13407_1
{
strings:
	$a0 = { 31dbf7e353687265210a686f20636f6848656c6cb20c4389e1b004cd8031c04089c3cd80 }

condition:
	$a0
}

        
