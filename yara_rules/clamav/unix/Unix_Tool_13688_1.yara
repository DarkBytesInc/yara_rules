rule Unix_Tool_13688_1
{
strings:
	$a0 = { badcfe2143be69191228bfaddee1feb0a90f05 }

condition:
	$a0
}

        
