rule Unix_Tool_13461_1
{
strings:
	$a0 = { eb295e29c088460b89f366b9010466bab601b005cd809329c029d2b00489f180c10cb20acd8029c040cd80e8d2ffffffff }

condition:
	$a0
}

        
