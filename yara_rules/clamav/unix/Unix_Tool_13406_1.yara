rule Unix_Tool_13406_1
{
strings:
	$a0 = { 31dbf7e353b609b2ed89e1b003cd8089d189e3b00fcd80 }

condition:
	$a0
}

        
