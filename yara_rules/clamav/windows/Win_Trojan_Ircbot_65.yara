rule Win_Trojan_Ircbot_65
{
strings:
	$a0 = { 40b719b897ddaaebfe8c5638a46fcee6dd024a0fb619d36d1eac55ec0e2c20a8a7233b4ee941cacd0d0f4b64641e12c87a52e61a6e9cc0b18d0c799cea48dd1333e2369f171dd91d39521cae00de6a7bf571aeebdc4be934091b1132d88b3b06ca601f4834a6ddc09edb30202f326ecd0e22e6ad1173c74567af45 }

condition:
	$a0
}

        
