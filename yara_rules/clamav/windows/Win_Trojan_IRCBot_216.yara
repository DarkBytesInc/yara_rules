rule Win_Trojan_IRCBot_216
{
strings:
	$a0 = { 2f6cc28f42951a747ef511e41106194cffd9cb0d7adcea2226b698d393587bca6c9c40f059f85b2bc1b196ffcdd20cc7eadf6c2ec6a77a291e65e6d402204dc834df51bcee378ee35de8d709fff9ea5be2096a3de21c6d4732f4cb28c2445ceee92398454fb31cb620 }

condition:
	$a0
}

        
