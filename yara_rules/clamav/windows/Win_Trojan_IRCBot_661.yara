rule Win_Trojan_IRCBot_661
{
strings:
	$a0 = { 27d46a6c4ead6cf24be14ec7a8541512473b2b6d5fd38ac6ec988f506cca0f97fc325695dfece508c59e00133b4362e6f0f8b4c4bae94c467facb126e6601483427ec0a10b0029aa7f3c92b12abf7e6355dbd30f577fa4a8bae87d9f35262a472deec7c1dbdc615ad84aa74b0402c95cd82c6000dbdd40ad }

condition:
	$a0
}

        
