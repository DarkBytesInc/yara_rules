rule Win_Downloader_Zlob_1700
{
strings:
	$a0 = { cbd3ff730f279544f16ce60b6cb33511a6ffcda0adcce8944765df7b9ceb5de54574033090ac7bc5c97840550bf2937e57c4babcb38aa5b4bd129b84a693c09e3fec239d0069f69f99b46f7abf778a3c1fb088f9fb4bb1337052 }

condition:
	$a0
}

        
