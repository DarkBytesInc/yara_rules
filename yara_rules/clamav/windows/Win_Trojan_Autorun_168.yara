rule Win_Trojan_Autorun_168
{
strings:
	$a0 = { 6b31f71e4096398c7ba4cbb4a707d629a61c79d8dcb1a685aac635527fabd5be6f28590422e6fcf51a3a8e531ec570721faf6dbb8e64c3d6e24e924bc7b89c9602aa5e96233ea0f421aeb2b04df07651bb9d322bde6d767172 }

condition:
	$a0
}

        
