rule Unix_Tool_13280_1
{
strings:
	$a0 = { 4831c9eb105e4889f756514889e64889cab03b0f0548e8eaffffff2f62696e2f7368 }

condition:
	$a0
}

        
