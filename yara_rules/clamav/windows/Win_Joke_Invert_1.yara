rule Win_Joke_Invert_1
{
strings:
	$a0 = { d8d0d4d0d8d0d4d0d888048827464b3bf376d05e83c620e2c5e8c8005ec3a06200d0e098 }

condition:
	$a0
}

        
