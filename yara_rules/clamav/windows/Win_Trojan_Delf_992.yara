rule Win_Trojan_Delf_992
{
strings:
	$a0 = { 699abcc0b418ffcbffffb0cc07e82023ffff07544f626a656374ff2591688bc064830c32c8debc7bf7605c5854062074504c05834844400c84807cb182f86f32908c3c7fbbfbcb388ce25f }

condition:
	$a0
}

        
