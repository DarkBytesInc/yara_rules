rule Win_Trojan_Gen_255
{
strings:
	$a0 = { b802009a7c025d0083ec02a102008b160400b90584bb08089a19055d0005010083d200a302008916 }

condition:
	$a0
}

        
