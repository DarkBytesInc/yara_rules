rule Unix_Tool_18227_1
{
strings:
	$a0 = { 3c06432134c6fedc3c05281234a519693c04fee13484dead24020ff80101010c }

condition:
	$a0
}

        
