rule Win_Trojan_Destoplug_1
{
strings:
	$a0 = { 81c3f8d7ffff33c985db8db708280000895dd476298bc1bb0328000099f7fb8a043a8a1c3102d8881c318ac38a1c3a32c38804318b45d403d7413bc872d7 }

condition:
	$a0
}

        
