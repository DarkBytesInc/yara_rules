rule Win_Worm_Collo_3
{
strings:
	$a0 = { 7600650072006b006c0061007000700065006e0020007700610061007200200068006500740020006f00760065007200200067006100610074002e00000000001c000000440061006700200065006e0020007300750063006300650073002c0000000000080000004d00410049004c0000000000180000005300430041004e00440053004b0057002e00450058004500000000000e }

condition:
	$a0
}

        