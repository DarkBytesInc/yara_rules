rule Win_Trojan_Fraudload_14
{
strings:
	$a0 = { ffff4dfef6583dffffff85ba18d022150effffffc35859ffffff81e9cedcfffa96f5cf7195ddc949fa0b26e591fb8a4aa0ffffcb5220fcfffff54abadb503dffffff092506ffffffff99c913b5bd7ee9ce8ffdfaeeac07cd03ffffff647a05fafffc92ae }

condition:
	$a0
}

        
