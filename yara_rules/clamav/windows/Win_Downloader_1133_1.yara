rule Win_Downloader_1133_1
{
strings:
	$a0 = { 9666db7e86b22312cf92384677b0b31dd9e736ea57333b95642b41bfc2a6b6071f9734f37c2e2d51dffbdffb765bcdf6e9b4f9bee64d09b6736f773572e32cbcccb9f9056d9fad407f0cafb5f5717db37534b229b7e57f990cb85cd8 }

condition:
	$a0
}

        
