rule Win_Trojan_Bancos_1760
{
strings:
	$a0 = { 3c182a9f1b58466b4fd2aa2195b4d0aa3c489a264cefd2476ca65bf41723a6294b8dfbce7f84d46e845941306c9a47023d3c9fc96714c79161a858f458b3bb26c2c649e5335f }

condition:
	$a0
}

        
