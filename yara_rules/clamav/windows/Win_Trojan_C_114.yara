rule Win_Trojan_C_114
{
strings:
	$a0 = { 6f63656d0800b6133a64656c617672691100c2137e315c25617643255c746261762e646174001900d8137e315c6176706572736f6e616c5c616e74697669 }

condition:
	$a0
}

        