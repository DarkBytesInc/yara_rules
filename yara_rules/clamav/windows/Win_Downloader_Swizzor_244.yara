rule Win_Downloader_Swizzor_244
{
strings:
	$a0 = { b7b00320fae52af8be6db32f04c6ceb5c6d96d0280c0a2bb65882533c8aa46db1fcb2cbcb55cf4b9c2f833197079727c36e56dc1b839051f565b221832aae2c27695aacd804d05aeed33fffe850effea6feb6c3a48dbf4d430d990f3f89185ab453f8f9075875ce7b2a0950ef8da4d409f00c3da046a2899 }

condition:
	$a0
}

        
