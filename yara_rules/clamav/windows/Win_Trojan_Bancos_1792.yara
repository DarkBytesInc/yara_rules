rule Win_Trojan_Bancos_1792
{
strings:
	$a0 = { 2b4b8a9eb77c70a599e359905a98128c10b521996366d772803cb5b21f22e7ee7671fc5c2b119e8c32e4a3c7729a93dc911d5bd89f8fe39e1793c7fb0e6e0c411b277eb95b43 }

condition:
	$a0
}

        
