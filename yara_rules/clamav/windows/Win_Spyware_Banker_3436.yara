rule Win_Spyware_Banker_3436
{
strings:
	$a0 = { 078eaafe2234e4c8e70297ac699536dbd5e8ca0a141fc1db1878f98ef97561b02b00adc8c207ab0c549458bd021d1b48a7a67c14bd73a04dd53b5ecbf9b9ee8ff2490523a54886b13c406659def5d14841cdd81e89e2fa47da0ee5585c8b58 }

condition:
	$a0
}

        
