rule Win_Trojan_Silly_39
{
strings:
	$a0 = { 565fe800005e81c6590056b103f3a489f25e4880c44fcd21723789f7b43ee83100b43fe82500803de974e8b8024233 }

condition:
	$a0
}

        
