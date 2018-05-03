rule Unix_Tool_13412_1
{
strings:
	$a0 = { 6a0b589952682f2f7368682f62696e545b525354590f34 }

condition:
	$a0
}

        
