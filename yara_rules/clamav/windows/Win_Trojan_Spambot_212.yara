rule Win_Trojan_Spambot_212
{
strings:
	$a0 = { c942d6d5c2b55e81323b94410db4c75d8dbf3ba057ffffffbfffb1a0a78017095a9ce18c213cc6cd0de7434c7fe42ae8f0312cf40668ffffffffbcb9ce9ec592c76c826c85525895c826480e297e0dca071c0ba001a79eae655cffffffffe590e7eaca19b467ef64e080f23058d1 }

condition:
	$a0
}

        
