rule Win_Trojan_Small_3650
{
strings:
	$a0 = { cbe7364e84cf4a43208df6bac6492562e17e347e50e3575d1d8ca7d8d66516382d8c8e13968c9cc021e393e823aa19fee4ab5f8522fb2d68fc1e7458ad6ccfb1314bcaa23466ce7046e785ea2f2f204532fc2ef3b7e3bfb4887d }

condition:
	$a0
}

        
