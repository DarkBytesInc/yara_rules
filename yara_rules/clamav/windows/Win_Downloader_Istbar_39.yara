rule Win_Downloader_Istbar_39
{
strings:
	$a0 = { 6de4721d506167650f266163636f756e745f69b1ddfecf643d687474703a2f2f77002e73407423b0c3b65c2e1e6dd86fd8b2d60a0b21356f0ef2b166f8417373695e2c175573652086ec16762018336e6f0e8d60cba40fd5c4b039dcc2a3bb2da7665b736ccc5aa9733b5f702e276d5b0506 }

condition:
	$a0
}

        