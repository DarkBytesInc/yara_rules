rule Win_Trojan_Spambot_182
{
strings:
	$a0 = { 055bb685124333c1cb322d8c0a6b4d9690adffff27f1f1e0eb915768d3bcb65fb36b3b86a5c0874021ffffffffaf061590fb9519ff5ad9c98846fc97c1f52638c0d21b95f3c6422837cfec4dd3ffffffff78c6ca07ae558176e6d9cbe5bddc6846ebe7c1bc74a1c8cd98846a950c }

condition:
	$a0
}

        
