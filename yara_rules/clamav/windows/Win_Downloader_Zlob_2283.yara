rule Win_Downloader_Zlob_2283
{
strings:
	$a0 = { c5408fe8e720023f9cf4b1f828929a8c6e4f938a4beefb7abd57ec920e0de5f57bfdedf3f1b7b0d65063ba70e0ad788ee64789c2864f667ba7157fa2b79361c345bed5af44ce1fffee59bba677cac08de02b8aa426900917c049 }

condition:
	$a0
}

        
