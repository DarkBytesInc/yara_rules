rule Win_Downloader_Zlob_1697
{
strings:
	$a0 = { a27ee5e6a8ff1ae6acee3af7592bf3288c6f69f11b053cc8e58cd0406397605ca47c9b84d685a914dcc26c6fca7bb2bf0697232646fdb15cbbedbfdc5c8db31e26dd3aa5e09649ad29fdba58b32f96c19d18bdae1350cdd1852c }

condition:
	$a0
}

        
