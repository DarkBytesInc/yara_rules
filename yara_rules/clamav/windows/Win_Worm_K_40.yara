rule Win_Worm_K_40
{
strings:
	$a0 = { 180800000900820024008200370082003b0182000100e4001b01e4007305e400900ce400ab0ce400c10ce400e00ce40011633a5c77696e646f77735c7a702e766273144f6e204572726f722052657375 }

condition:
	$a0
}

        