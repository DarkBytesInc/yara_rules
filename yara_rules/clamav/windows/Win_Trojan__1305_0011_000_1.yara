rule Win_Trojan__1305_0011_000_1
{
strings:
	$a0 = { c74515000026c745170000ba6707b440cd21268b4d0d268b550fd0ce80c664d0c6b80157cd21 }

condition:
	$a0
}

        
