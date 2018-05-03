rule Win_Joke_FakeDel_11
{
strings:
	$a0 = { 5c436f6e74726f6c5c4b6579626f617264204c61796f7574735c25 }
	$a1 = { 633a5c77696e646f77735c2a2e2a }

condition:
	$a0 and $a1
}

        
