rule Win_Trojan_IRCBot_345
{
strings:
	$a0 = { 996bc4555f1a560eb377305e25c7e5aadae2e226e08772a2fe71a4a662d256fabe78a5a20e34f12129296e27ceb9e946b8e1a4d91deb19a4848caf8d73e0ec8b6961f3fb9da45ab1dbdbbc620d806c0ae83cbbf1a91c62ef1bba986a9e2bb2 }

condition:
	$a0
}

        
