rule Win_Trojan_Krapodnik_1
{
strings:
	$a0 = { 035b83eb032ec68607005b2e8a863f028807432e8a8640028807432e8a864102880783eb02532e81bee201c800 }

condition:
	$a0
}

        
