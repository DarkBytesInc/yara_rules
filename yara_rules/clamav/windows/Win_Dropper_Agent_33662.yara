rule Win_Dropper_Agent_33662
{
strings:
	$a0 = { a365cda0d765be563d91f195f6d7873d6fc82b94f3cd3128b1747d08c4f578bd696811ba3c62aa5e4a8c27f8d214381a0e40bfe12f28c5f3baa48dfd132bb24b85dacaf3891972b51835b3e47535a039 }

condition:
	$a0
}

        
