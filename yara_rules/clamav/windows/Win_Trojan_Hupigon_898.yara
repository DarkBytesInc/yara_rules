rule Win_Trojan_Hupigon_898
{
strings:
	$a0 = { 36d1bb47c8c7ca61c52a0e9761b3a1ec3131d9cec342ecf15d4c6666ebc7719618cbe4e5f5b51f3fa43e6eca8f84c8b7e1c67dc7f8d0af1bd652f6129b219fa2187c2d9c37afdd24c11711ccd1e3f3a135eb7ff69ec89cc56e7a472caefde3 }

condition:
	$a0
}

        
