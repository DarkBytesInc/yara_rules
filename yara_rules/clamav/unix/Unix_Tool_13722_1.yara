rule Unix_Tool_13722_1
{
strings:
	$a0 = { eb115e31c9b137806c0eff1380e90175f6eb05e8eaffffff44eec32ae09344d3637b7477828a7b7642867b7b424278879cf679ccc914c322e09353e093 }

condition:
	$a0
}

        
