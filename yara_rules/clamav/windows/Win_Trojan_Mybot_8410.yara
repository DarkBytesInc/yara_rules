rule Win_Trojan_Mybot_8410
{
strings:
	$a0 = { c438239d75bcc6f1624c1a6fca02626b86d1b2f528e59a888b44ef8f6e42c3201b75f1ee55c3ecac2fa0897c8a358bcbc6c226028197afbe189df619caef994d8c9ed1b6c546825f83d2dd7f9e026d2ed15d42f3d0 }

condition:
	$a0
}

        
