rule Win_Downloader_1390_1
{
strings:
	$a0 = { d4e40f52d866cec57d36a4cb1d2473564db91c5edf64c4a09d6c78accfaac7d5296792df30f1cb1bbd67f0dcaea456b21ebc4fecb3971fcab777a176db402894e8cd007ebf41e3a1ecf9e63d42123d7a6c9e3548d90fc79d9d230e55dea324332faa99 }

condition:
	$a0
}

        
