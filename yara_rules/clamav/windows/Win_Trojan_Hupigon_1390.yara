rule Win_Trojan_Hupigon_1390
{
strings:
	$a0 = { cad9b44ef9de9fdde33a5450576acd068f354d18cc1f705e1504e5d50e1902f2535817f89bcc92d7ff6937bf9dded4303b453ed79724faaa571c45ea5a9c73e3d3fae896bf1fa9681862bf64f76ce8f5b7076789629756cc2fbfbba3a1c30dbde62bc6bfc2d6718fc490769cf6fc316df435d711dac1 }

condition:
	$a0
}

        
