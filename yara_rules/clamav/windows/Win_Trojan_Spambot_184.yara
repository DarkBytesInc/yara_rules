rule Win_Trojan_Spambot_184
{
strings:
	$a0 = { 7360059dd06adff0b4b22e26a365c579fbade49161856155ffffffff4c77930117b5a9c348f16653256b4b6732fc0cda7c4879e1913d30a81bbb865cffffffffc50e2651a8cab3f664b8ad90d5e9c00a2bec4bcaeb0806af4084a03b8b9763bdffffffffebc109c748cc8f20a7b4 }

condition:
	$a0
}

        
