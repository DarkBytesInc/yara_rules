rule Win_Trojan__1305_0006_001_1
{
strings:
	$a0 = { 21a17b07e83e00ba8307b91c00b440cd2126c74515000026c745170000ba6707b440cd2126 }

condition:
	$a0
}

        
