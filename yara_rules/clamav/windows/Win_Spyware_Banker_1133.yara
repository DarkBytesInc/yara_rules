rule Win_Spyware_Banker_1133
{
strings:
	$a0 = { 4e3e3792f068cff7f3ba98bddb99ce8beccdea65c4303135a252ebaf37a761d918bb80b1b1c6039d1ad1662b5358a79afa259c93c61a91e537a3f730bf66cc91b1fe467d1605040254cd4cd6ffaea060b8cb6a572d136ae188c6 }

condition:
	$a0
}

        
