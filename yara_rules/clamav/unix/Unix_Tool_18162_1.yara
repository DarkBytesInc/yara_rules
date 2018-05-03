rule Unix_Tool_18162_1
{
strings:
	$a0 = { 2806ffff3c0f2f2f35ef6269afaffff43c0e6e2f35ce7368afaefff8afa0fffc27a4fff42805ffff24020fab0101010c }

condition:
	$a0
}

        
