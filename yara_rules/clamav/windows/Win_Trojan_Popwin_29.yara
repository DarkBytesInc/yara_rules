rule Win_Trojan_Popwin_29
{
strings:
	$a0 = { 43bb6316f1abe7618abafc996c9a6ccbc030eb9f05af2b91e41e9ee5e4bd54866f35b71bd5dc4065389c5f3fcf5a7c9a9126f0baf6d0a2c94c54e9b3883127cc1c9ffccb8b12db22999e1defb6a3337fe87f590489a82ebdccf1b49c49f77226ef0ba335e139f5ae84f4f22d8b821a8777304eaa3fd987e18e3b }

condition:
	$a0
}

        
