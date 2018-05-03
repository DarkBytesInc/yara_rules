rule Unix_Tool_13279_1
{
strings:
	$a0 = { 4831c099b03b48bf2f2f62696e2f736848c1ef08574889e757524889e60f05 }

condition:
	$a0
}

        
