rule Win_Downloader_Small_4597
{
strings:
	$a0 = { 44656c65746546696c6541436c6f736548616e646c6575db27bb726561196c737472086e }

condition:
	$a0
}

        
