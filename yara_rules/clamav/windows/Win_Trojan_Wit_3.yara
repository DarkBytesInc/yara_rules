rule Win_Trojan_Wit_3
{
strings:
	$a0 = { 37018bf087ed8bdbbb2d0a8bcb8adb4f478a148aff80f22f8adb80c2088adb51b10786dbd2c28bdb5988148ad28af64686d2e2db5aedd544d82571b273d8ee57221f7386d1b0ab92c8410b91d5cdec5aedd544d825225f73c6265fab }

condition:
	$a0
}

        
