rule Win_Downloader_Small_1135
{
strings:
	$a0 = { 57506a006a00b92c020000bf4851001068002500106a006a00f3a5c744242000000000ff153c4000105f5e59c39090909090909090906aff686b36001064a100000000506489250000000081ecb408000056578d4c2408e8ca0700008a0df0500010be48510010c0f914880df0500010b92c0200008d7c240c6800700010f3a58d4c240cc78424c808000000000000e8a20800008d4c }

condition:
	$a0
}

        