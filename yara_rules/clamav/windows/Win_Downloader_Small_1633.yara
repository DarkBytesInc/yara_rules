rule Win_Downloader_Small_1633
{
strings:
	$a0 = { ffff7f????4000ffffff7f0000000000000000616476??????0000687474703a2f2f[15-20]2f00[0-8]687474703a2f2f[8-10]2e62697a2f70726f67732f00[0-3]5365446562756750726976696c656765000000[0-8]0000000000558bec81ec??0500[0-2]5356576a??59be }

condition:
	$a0
}

        