rule Win_Trojan_SillyOC_29
{
strings:
	$a0 = { ebeb5b900d0a5b436f70797269676874206279205a65726f436f6465722f2f58475d5b414e5332414c4c2076312e32 }

condition:
	$a0
}

        
