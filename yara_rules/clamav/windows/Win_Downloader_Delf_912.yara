rule Win_Downloader_Delf_912
{
strings:
	$a0 = { 1b1f43f7c579f71c8753988042605d7ad6dbe4568aa3b4cf4f9f6d7c814df3b563d63e0effab99d5f312bd3cfba19d70060b1e672f534dfc046eee1b8538b58a8c61ca508cb68c6f7854e06d1a62018ca605a45dce2fa8e6da247d64bf124d2e74170aca }

condition:
	$a0
}

        
