rule Win_Trojan_Hacdef_65
{
strings:
	$a0 = { 458ddb61808751f8a9bfccae2c8b1015ec3c4c9f292024ebf1f5ce9c2c07d17c777c5c9f94ff80e3b4cb51c32e7c8ce76164d112bb8028de6cbc1d84ef4e8b5b71fc5ba0b9fe0cdcf501c425f3e6934499274b1b050bc3e33d9c4f5c327d84e531149464 }

condition:
	$a0
}

        
