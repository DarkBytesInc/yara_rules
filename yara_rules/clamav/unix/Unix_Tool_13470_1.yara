rule Unix_Tool_13470_1
{
strings:
	$a0 = { 6631c068090066b8ffffffff66506631c0b0256650cd80 }

condition:
	$a0
}

        
