rule Win_Trojan_Lanus_4
{
strings:
	$a0 = { 646f7768696c6563363c3e223c212d2d68746d6c2e6c616e75732d2d3e22[0-21]77726974656c696e6528633629 }

condition:
	$a0
}

        
