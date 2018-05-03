rule Unix_Tool_13628_1
{
strings:
	$a0 = { 6a0b589952682f2f7368682f62696e89e331c9cd806a0b589952682f2f7368682f62696e89e331c9cd80 }

condition:
	$a0
}

        
