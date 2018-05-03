rule Unix_Tool_13679_2
{
strings:
	$a0 = { eb1131c0b004b30159b2cd80b00131dbcd80e8eaffffff }

condition:
	$a0
}

        
