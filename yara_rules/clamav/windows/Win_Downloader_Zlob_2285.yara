rule Win_Downloader_Zlob_2285
{
strings:
	$a0 = { b4048207fd076aade00b5081108ddacbb8c9aebfa9b168d022d48427ff35ac95fa317247e7fa7e35da3bf582dbf1cbfca6339ac819e44ea41e197fb626f5a9be95bcd7c6b546d82fb455b5c30fb1a40c89d347a480e0e0f3699c }

condition:
	$a0
}

        
