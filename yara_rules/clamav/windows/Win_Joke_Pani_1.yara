rule Win_Joke_Pani_1
{
strings:
	$a0 = { 696e7374616c6c6564207570736964652d646f776e21212400000000 }

condition:
	$a0
}

        
