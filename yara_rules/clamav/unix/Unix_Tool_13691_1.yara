rule Unix_Tool_13691_1
{
strings:
	$a0 = { 4831d248bb2f2f62696e2f736848c1eb08534889e750574889e6b03b0f05 }

condition:
	$a0
}

        
