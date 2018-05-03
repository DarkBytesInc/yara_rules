rule Win_Worm_Antinny_21
{
strings:
	$a0 = { 648921b201a13cb34000e83d3affff8945f4680cf540006814f540008b0dd4144100b201a1e8b54000e86edfffff8945d433d28b45d4e8e5dcffff8d55d88b45d4e8cae9ffff8d45ece826feffff8d8574feffffb924f540008b55ece8af45ffff8b8574feffff8d8d78feffffba3f000000e8397affff85c00f85ef000000 }

condition:
	$a0
}

        
