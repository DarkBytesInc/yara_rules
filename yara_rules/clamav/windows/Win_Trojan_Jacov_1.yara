rule Win_Trojan_Jacov_1
{
strings:
	$a0 = { dae76962a8b136ac76ecd15f549e879ee1c054a20c0b360238170a61300e23093a0e30617d4f231923617d4f38176800e8fdffb003cf8db617018bfeb91001ad }

condition:
	$a0
}

        
