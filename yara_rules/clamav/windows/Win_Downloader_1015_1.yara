rule Win_Downloader_1015_1
{
strings:
	$a0 = { a8a7b12f3aa80eb66d6660ab3b17203f3360dbd84669397684c1e4aeb335dbcfe3e0b23a42e00240e0c4e1bdfa3a55b2ad5e23452f1ed200eb90b21fef47233f6aa8cf48538c39b7cf86ebe9bb40c8e8eef6fbafc182410ae265b802 }

condition:
	$a0
}

        
