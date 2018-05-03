rule Win_Worm_Gaobot_24
{
strings:
	$a0 = { a9c06b95b1e2f60b1508f23272c8830360d9fb480b1a2e159b8ee572aeafd4f14ef3ca7c9c9a25e968a3e3e9a194f702cade251f9ab9e87fbcff4b104c1977ac38ff5806120c19fd80e1453bc763f8ca2a2e01c8cad08c6f611a1a1dbe9f52abf3f9aa7a7cb1bb }

condition:
	$a0
}

        
