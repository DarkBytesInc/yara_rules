rule Win_Downloader_Small_1212
{
strings:
	$a0 = { 6562652020202020202020202020202020202020202020202020202020204861756e617179727120726b707263677662612020202020202020202020202031 }

condition:
	$a0
}

        