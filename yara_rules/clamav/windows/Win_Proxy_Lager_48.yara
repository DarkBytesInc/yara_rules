rule Win_Proxy_Lager_48
{
strings:
	$a0 = { 08af4ba376c677ac6eb1b4714abacfd1b3c5ac81fe80aaae113320d79e5f59c18bc49bf10036fa34c212abb9c614a237828a4e44e48f7c6fcddb8481fd1eb7f3b6eade64206a }

condition:
	$a0
}

        
