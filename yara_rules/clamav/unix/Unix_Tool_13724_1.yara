rule Unix_Tool_13724_1
{
strings:
	$a0 = { 31c0b0256aff5bb109cd80 }

condition:
	$a0
}

        
