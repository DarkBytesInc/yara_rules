rule Win_Downloader_3864_1
{
strings:
	$a0 = { 83ec106a006a006a0068001040006a006a00ff15ac404000e87300000085c074338d442400c7442400a861400050c7442408702b4000c744240c00000000c744241000000000ff1520404000 }

condition:
	$a0
}

        