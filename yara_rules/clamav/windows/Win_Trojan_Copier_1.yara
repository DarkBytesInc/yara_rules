rule Win_Trojan_Copier_1
{
strings:
	$a0 = { 666f722025256a20696e20282a2e62613f202e2e5c2a2e623f7420633a5c3f2a2e2a617429[0-15]2b25302025256a3e6e756c }

condition:
	$a0
}

        
