rule Win_Downloader_1099_1
{
strings:
	$a0 = { 1eb40061a21543f2b6a83c0be570b0fa19b670c2d8023235b5d065da14b08ff4daf29a382cf2c8b1639f9acde776b212a127ff27ffcc70c60405cba500e699f846db36b2f76347b5686e273ab36560e4f5fdbcaff5ff03059cade3fe }

condition:
	$a0
}

        
