rule Win_Downloader_Small_2940
{
strings:
	$a0 = { b35fbfe22000a2b0e14f8de20e41b1118c152acb2659b1f9b3696ebf8f8d5be250c5b0fbb21dd9e2d0ba83498a811975b38b8fe684de6c4d089d8f573e5f3fc469ef41433ad56d368357d139515a57d5e66b60da6c1dd7e07c88f29be97eb54d957f6cdaea1b260fb93451088b048d065f5f }

condition:
	$a0
}

        