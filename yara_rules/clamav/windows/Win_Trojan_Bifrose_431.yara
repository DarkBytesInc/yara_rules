rule Win_Trojan_Bifrose_431
{
strings:
	$a0 = { a98faa3a799c709e9eaab42fa653bc507b03a131eb9c79fd93cea569eafbb2d184abacbfc6d11b9a6a46b9bf4bdd5b7cd64c940ba9abe1fcb992b571c067d3745f987bc97d74ca6fb27241275859db2bf57b013bfefad7e8d86efeeb0dc5898dc3e8a8e7e57c08ecfdd934dc5f3908109b54a16c2267ef7bda04ac4529 }

condition:
	$a0
}

        
