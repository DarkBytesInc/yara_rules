rule Win_Downloader_Swizzor_395
{
strings:
	$a0 = { 6d1e62dd9f9f63503a4639b5540e6ca2d06cb50154bacd02fba1b62e66e3d980f7d2541a78878235f7defebded1feb0efd579cfb6c4a7d90f7fbff14eb01b3f5003b3ecf81dbfc840e92b69c3beea688397b1f288b5394d6a46e }

condition:
	$a0
}

        
