rule Win_Trojan_SdBot_3723
{
strings:
	$a0 = { 615d6fceec88b0abbfebf3cde4ba7fb54c9fc2c51b260fc080cca8dbee621e18a1c920bf653aae61951b02a2250bd6b8f47e9dc6fd448765206cb7b733351eeefcf4ba23b994f6e7a3fec3ae08e32c0e04d8c0b5b26f87b55c88be0f82a4bf3f7a416662509ce5ec76d8cedfd339 }

condition:
	$a0
}

        
