rule Win_Downloader_735_1
{
strings:
	$a0 = { b13fa8531bc58465e6bb26fa5a15f30edc82e951967c957adb527172b15c6ebef1cda10b95515cb0c57cb2016a65cb381f36c61dea5865ef83bf2ef48c8769382a27bb344bd6fb2c38c7ccecc6ff92e79b497cd74a802929782a5b9f413fd0dda6ff00ad }

condition:
	$a0
}

        
