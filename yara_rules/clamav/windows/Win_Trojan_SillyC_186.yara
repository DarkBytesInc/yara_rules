rule Win_Trojan_SillyC_186
{
strings:
	$a0 = { 60833e01010074062e83060101038b3e0101b8001a8d954202cd21b8004eb927008d953202cd217308e9d600b8 }

condition:
	$a0
}

        