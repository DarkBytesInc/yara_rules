rule Win_Trojan_Delf_1158
{
strings:
	$a0 = { 558bec83c4f0b8b01c4500e80d005770a15c2e45008b00e80d04db1868c01e45006a00e80d005d8485c0755fa15c2e45008b00bae81e4500e80d04d73c6aec }

condition:
	$a0
}

        
