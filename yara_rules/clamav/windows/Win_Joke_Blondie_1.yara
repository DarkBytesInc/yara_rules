rule Win_Joke_Blondie_1
{
strings:
	$a0 = { 42006c006f006e006400650020006a006f006b00650000000e0000000001 }

condition:
	$a0
}

        
