rule Win_Downloader_1150_1
{
strings:
	$a0 = { 207796685b033626e73828474db7454da83c8e132c422f7bd8d33d1c0863806ecefc084e2e01dbef5024c0fd2e9aeec8c35ce4fec69a68f02b760bddf944fa95ca3a4ab0dcfb8f7c4d7708e26e35d2b679b63bbac1bef4c3fd90641e }

condition:
	$a0
}

        
