rule Win_Trojan_Magania_18
{
strings:
	$a0 = { 40519a2373849cb426f0f56da90d7328d90e6e946739783fe4ce9fa9e62fc36b34618218cb2987b2ffd42a8bcdbe4acafa414ae0f1c650eab8e7b30d80b63f91fe46da8a3a89d5174cb4c1a3235c5ba247b75e12978ad073d8606897945eb3c8ba84cb08 }

condition:
	$a0
}

        