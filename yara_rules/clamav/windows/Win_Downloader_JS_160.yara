rule Win_Downloader_JS_160
{
strings:
	$a0 = { 22736372697074695c22265c226e672e66696c5c22265c226573797374656d6f626a6563745c }

condition:
	$a0
}

        
