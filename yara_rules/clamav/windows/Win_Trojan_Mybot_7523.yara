rule Win_Trojan_Mybot_7523
{
strings:
	$a0 = { c9fdfc1c1e9e567ba49dac5182187b17c3488cc8e38c2091175705266ac32ebb2fbe1a696cfd98aeca995947e09f2e2a7be1052545ae9f7e65274f880ba2a554a85a6df58561a544b95ffaee85df248d2183c413956788111eaf7c66996e45d5e0eb4178ebb03ffd14f3d45e000080000000689da566e070e6550692e6acd6ab895cbcdc84fed6f5aec012a453abe780cf }

condition:
	$a0
}

        