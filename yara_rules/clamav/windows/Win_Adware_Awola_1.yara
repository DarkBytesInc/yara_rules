rule Win_Adware_Awola_1
{
strings:
	$a0 = { a432e0a432e0a432e0a432e0a432e0a432e0a432e0a432e0a432e0a432e0a432e0a432e0a432e0a432e0a432e0a432e0a4322c2c0000000001000000600d6c0041776f6c6120416e74692d537079776172652036 }

condition:
	$a0
}

        