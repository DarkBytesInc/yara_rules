rule Win_Downloader_Small_2460
{
strings:
	$a0 = { 712f0c22d852a4bfedfb685fcd8604ab26a60833818a233f72442c67455d252e8ea724e299c73787c56ecc5a76852a1a8bacf25b1244908688f272cbeac773d7ba904ec1f1d6fd11865447c1fdb348c1e8d20fa1c8ce6c2b74ddacb593e16fc9e4c36ec6c5cb6ec1c8 }

condition:
	$a0
}

        
