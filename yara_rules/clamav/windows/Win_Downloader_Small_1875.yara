rule Win_Downloader_Small_1875
{
strings:
	$a0 = { 2e397335ea3477366f3208e3616476a330f165782a108a20fdf23173ed66b946ba6a767467c0076e6f3231373b }

condition:
	$a0
}

        
