rule Win_Downloader_Small_3151
{
strings:
	$a0 = { d7c2004cd1c11661c854aaa06cd6bf5286ccb068b2c777ebfc61d43783bb14e155132b76dfe23041dac71687f546c975f9cbe47b99f44cfbd380a9c2ddc0ffb946cddc33d36ed970d2f04276d1c033b29ef46f0199fa6a18e5c874a263c86fa9bfd614087d7989fdecc20875e1d70e754880e176b6317f58ebe0c681a1c4a56eb4d1250fe2e27c690c7ad46b1b3aa2b41502dffdf7c1 }

condition:
	$a0
}

        