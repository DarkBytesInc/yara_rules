rule Win_Trojan_Mybot_8440
{
strings:
	$a0 = { ef1c687eee51dab2fe84ac350a79385d18edd7a4c20dff15c4f3ca707739405e49cd3d71f2ac6fe272ab2aca82173c5a52cd0339c725731b7a353e705ba451e010f74c6647db5326268943ebd6fdc595f328475dc8 }

condition:
	$a0
}

        
