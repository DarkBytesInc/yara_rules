rule Unix_Tool_18154_1
{
strings:
	$a0 = { 17e34e240bc33a230be302c703645a256a260bc32f62696e2f7368 }

condition:
	$a0
}

        
