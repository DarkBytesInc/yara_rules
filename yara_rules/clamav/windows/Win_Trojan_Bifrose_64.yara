rule Win_Trojan_Bifrose_64
{
strings:
	$a0 = { a98faa1709c65c7e4624cdbb52273337ef1ba4533de83ea794b8d6e581c0bf59629de208faa4b792b5573cb6e2dd5b7cd64c940ba9abe1fcb992b571c067d3745f987bc97d74ca6fb27241275859db2bf57b013bfefad7e8d86efeeb0dcd898de252f8c386f20a1a8bebae5c5f3908109b54a16c2267ef7bda04be5a51 }

condition:
	$a0
}

        
