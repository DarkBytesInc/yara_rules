rule Win_Trojan_Hupigon_815
{
strings:
	$a0 = { febda4ef20a2b11110f3c139f098e5103000c043982e372c4f5f2ae2db0a1cc3513824440d78a5b28d12fbf9974a7b02a22733eba68de4c850a73bfcb723deb3258809a6e37ffddaba44a8bf1d8372ac7aef13bbfd40e3e80f673460fde0db74b9bfb12c360ba55191182f8d4ac5 }

condition:
	$a0
}

        
