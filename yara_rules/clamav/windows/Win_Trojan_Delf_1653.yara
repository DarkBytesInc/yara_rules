rule Win_Trojan_Delf_1653
{
strings:
	$a0 = { 68669b400064ff306489208d55ecb8809b4000e8b5f3ffff8b55ecb8f0574100e82cabffff8d55e8b8ec9b4000e89bf3ffff8b55e8b8f4574100e812abffff8d55e4b84c9c4000e881f3ffff8b55e4b8f8574100e8f8aaffff }

condition:
	$a0
}

        
