rule Win_Trojan_Agent_33356
{
strings:
	$a0 = { f98baed10e646b7f5ef8a150360c2b92b94acc11a08a0c9fce09639e29684e49187303cd398c0b407e8c737abde2448bafb8a52aa493a9e8a73eec5b3f5d18b324d2c50ccf3340248186146c4ac7 }

condition:
	$a0
}

        
