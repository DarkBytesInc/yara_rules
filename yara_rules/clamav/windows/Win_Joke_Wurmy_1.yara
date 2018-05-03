rule Win_Joke_Wurmy_1
{
strings:
	$a0 = { 5343524e53415645203a4c697a61726473 }
	$a1 = { 487676511e394646223939464c4646d1 }
	$a2 = { 7a7a77777a7a7b7b7e7e }

condition:
	$a0 and $a1 and $a2
}

        
