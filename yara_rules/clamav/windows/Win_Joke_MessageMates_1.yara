rule Win_Joke_MessageMates_1
{
strings:
	$a0 = { 558bec6aff688054410068f03b400064a1 }
	$a1 = { 5c436861726c69654e65774d6573736167654d617465735c416c69656e7a355c }

condition:
	$a0 and $a1
}

        
