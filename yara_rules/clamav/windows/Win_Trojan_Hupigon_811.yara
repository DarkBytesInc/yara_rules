rule Win_Trojan_Hupigon_811
{
strings:
	$a0 = { 0460f07fc46b63acf8857ff993f9be9b787aa3de7724e1d0e7dfb6a52d8f8f23ac19dbcca1cb1275639839ebf62ef6e4ec20a178d70d724586a1a2176577d496b319ba116510c52d9cd7f9f9bda6ae112e5a65bcd318b838cda16940d52593 }

condition:
	$a0
}

        
