rule Win_Trojan_Worm_44
{
strings:
	$a0 = { 9fb0554c437e20d97dd7520aa9c0bc69767930d19d1952960339e6d9ceb0c500264fcf16f76ec9fd062094fc4a55cb7c388d2ce6f28b0aa623bb4120a64fbe8eb8d4ed3c2fad51818a8ae4aacaffd2638097e126bccf7adef18e8882187590b6feec17c17910dacd2511f7b7c6a1f5ef }

condition:
	$a0
}

        
