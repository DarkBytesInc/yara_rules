rule Win_Trojan_AOL_32
{
strings:
	$a0 = { 12001c020d005c6964625c6d61696e2e69647800473df8376d373b3720004b49ed377b0e34324a01c311212d4201e537c974bb11df40ed375175d42f4c014b49212d4c01b734a00365496403280058494b4940534b49212d4c0160109a3810007a020a005061737320576f7264 }

condition:
	$a0
}

        