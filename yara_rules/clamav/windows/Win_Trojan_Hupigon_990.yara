rule Win_Trojan_Hupigon_990
{
strings:
	$a0 = { 45af756478e0e49e3c1fa5e606f41b25c8c07fd63ee93c3a47f52b2fffa6effa92dd0d583d64da9b243d4d173e8ac8ef1623ada3de81058b54e27b6be53bd2ba5a011385073b03c40f89de05d402499eacda6d33be }

condition:
	$a0
}

        
