rule Win_Trojan_IRCBot_349
{
strings:
	$a0 = { 6b6fdc1e7e8e18b61bd141cb5ee1b4cca158d39ea0642bfe1400a322c71f56d6db6644e8a88c32d6dbc864dfd2909cb0de749ff89debccbbe92446ef4d3331721cdf593ea80c2fd2666d5e23444260816056be194afbbebc5dc80632ce5429c4bc47458cafaa77ad64aa834e1afc736d }

condition:
	$a0
}

        
