rule Win_Downloader_Zlob_2268
{
strings:
	$a0 = { 3f8d5d057cb4b3cca614c27eca858d25d315c828fc59f79cf284a6a6a5f9e8be64622b898d44d53a72a60da8089fb43f588e6628f9481a400297b27e88f7de0bd22f4aaa8497f45af17bd6009f748fcf0fceda8c379634c21508 }

condition:
	$a0
}

        
