rule Unix_Tool_13384_1
{
strings:
	$a0 = { 688ae2ce8168b10c5354686a6f8ae4680169306368693074696a1459fe0c0c4979fa41f7e154c3 }

condition:
	$a0
}

        
