rule Win_Trojan_Fakealert_112
{
strings:
	$a0 = { c9762302f3bf94c30f372bbe4c5e3a78b74336c9d33c33b7cd3ddaffef2614539ed37d7b543f6a0cf4bc3c32393d67abffbcb51f30e20ff3b72fe261ae32f8c6fbbc5e43dda3fef74c3c6b94e5a8e674d0e76e565c5893d8cb3a40b81936270a1f553972 }

condition:
	$a0
}

        
