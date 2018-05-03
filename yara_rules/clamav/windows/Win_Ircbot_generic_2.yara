rule Win_Ircbot_generic_2
{
strings:
	$a0 = { 6b6e6f772e207d444d327b202856352e3029204d495255532e0d0a6e33313d6f6e20313a6e6f746963653a03302c304a }

condition:
	$a0
}

        
