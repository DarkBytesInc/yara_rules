rule Win_Downloader_Small_3201
{
strings:
	$a0 = { 9ae0ac46e35fac44ef61674168590d420b1327fc5fe09d4070552a4df845f9faef815908b20e448c67efa53eb0081413fe45395d2a0a0d119a04792e3745391eb814bcf987f1 }

condition:
	$a0
}

        
