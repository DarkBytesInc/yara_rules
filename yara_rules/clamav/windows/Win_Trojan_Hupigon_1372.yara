rule Win_Trojan_Hupigon_1372
{
strings:
	$a0 = { 0d410df5e4d4079982fdf9a5b89a43e13932ca43aba93c99a974fd6ef91258466bac31b981afefe1cbef6ebc71c971c91d56e46f859b582b9fb720e695af0ca64130892845f083ea0dc5e2d2d3f18fe2ac78a0fa1cc38edd8381d1ab3280d38607a6 }

condition:
	$a0
}

        
