rule Win_Downloader_986_1
{
strings:
	$a0 = { 9db5de626765241cb927afe63267aaac6474b970e55f20c2e8b127d4047ecde8c143e817ce3e3b59a2103de14a323fe03a6200c1056f3680c3e22b0e7dc8c82cfa45ae3f9fb1019e21d4580ff1f57e79d0cfb2d4aa91a5a3dc0df87e }

condition:
	$a0
}

        
