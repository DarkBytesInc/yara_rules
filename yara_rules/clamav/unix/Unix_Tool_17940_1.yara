rule Unix_Tool_17940_1
{
strings:
	$a0 = { 2406066604d0ffff2806ffff27bdffe027e410012484f01fafa4ffe8afa0ffec27a5ffe824020fab0101010c }

condition:
	$a0
}

        
