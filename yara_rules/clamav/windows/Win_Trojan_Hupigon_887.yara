rule Win_Trojan_Hupigon_887
{
strings:
	$a0 = { 63d2a8bf72537a23511e43805f2e5aac33a8a2af2c21fc22cbbc1d15e95ba687b41036dbaa53acfabcfa5b87b26e072e36e57dfb127ff603e81acf250cac90725ba06e24409c18c8df6ce741d904fde7d33b1a70e8f834484a23fbb890a677 }

condition:
	$a0
}

        
