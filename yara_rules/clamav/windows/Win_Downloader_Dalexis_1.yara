rule Win_Downloader_Dalexis_1
{
strings:
	$a0 = { 52be0000000056beffffffff568b0d????4000ffd15a5985c00f84????ffff68????40005b[0-10]29c7f7df5781f9740600000f84??000000[0-30]0333[0-100]f7d6[0-5]83ee10[0-30]31d6[0-30]8d7601[0-100]568f07[0-70]68????4000c389e7[0-70]ff27 }

condition:
	$a0
}

        
