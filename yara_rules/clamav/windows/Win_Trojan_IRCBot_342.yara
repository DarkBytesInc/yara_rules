rule Win_Trojan_IRCBot_342
{
strings:
	$a0 = { 529122c248a2679528132cf597d75892378ae8fef0b567cc5d7c1fac4bce21414db71eab33b3dd531636c6b72631462ada5bd0eb092dddcaf2ba54a7d253d354f2bd48ddc647c748f48873b20d3078b8 }

condition:
	$a0
}

        
