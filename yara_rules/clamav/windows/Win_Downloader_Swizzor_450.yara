rule Win_Downloader_Swizzor_450
{
strings:
	$a0 = { 5a87e14c8509c09a19cdb6d8ce098d3ca96d19b88cdfc57bfc6e7f89b12fbd2f812dba9e60081cee61e6e9ec706b29cf0dad5b4bf4d70e8861048652afef58640588881237b725c9c0f32cba5c066a6f887e1bcf5a2cb94ffe07 }

condition:
	$a0
}

        
