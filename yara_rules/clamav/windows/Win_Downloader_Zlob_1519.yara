rule Win_Downloader_Zlob_1519
{
strings:
	$a0 = { 0d651f759c26e6fed665639a513e2826563f4cd85245915ef4e6ab778db7221bc3b68f83ab372a7be5b38f749ddd5b6a6845df4cc36fca572844cbee2739450965c43cfbda8e997e1b1db8d70e2cd02d05b1 }

condition:
	$a0
}

        
