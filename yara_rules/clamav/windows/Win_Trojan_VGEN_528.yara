rule Win_Trojan_VGEN_528
{
strings:
	$a0 = { 032ec686190900e83c0706b452cd21268b47fe072e89866c09b430bb1313cd213d77777503e9a4003c05724db8 }

condition:
	$a0
}

        
