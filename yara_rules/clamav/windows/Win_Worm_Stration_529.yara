rule Win_Worm_Stration_529
{
strings:
	$a0 = { 5c0000002e657865000000009eb9b1b8a5bab6a3beb8b9d70000000092b7a3a6b3a2e7b4b2a4a4a2b4b4a1b2ababbee7aea9b4b3a6ababa2a3e9c700b5a5eaedf6a5b598000000001f11061a111847465a10181874 }

condition:
	$a0
}

        
