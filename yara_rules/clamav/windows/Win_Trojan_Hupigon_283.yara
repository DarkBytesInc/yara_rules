rule Win_Trojan_Hupigon_283
{
strings:
	$a0 = { 9875c76a1f846a56dc97b8f67dc005d841e9b6a6913b08869a0d76da1f1de54ef164fc6b698bff9159766020228b4c09f18b4ae11562b8a04f7ef2a2a23c2bd1429830d4a0771e2cafbb75fcc13e75eb2fdc8a4d3aa2d7b83619 }

condition:
	$a0
}

        
