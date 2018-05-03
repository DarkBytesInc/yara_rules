rule Win_Joke_Fallingicons_1
{
strings:
	$a0 = { 46756e5769746849636f6e73 }
	$a1 = { 456e6a6f792c0a4c697a617264 }

condition:
	$a0 and $a1
}

        
