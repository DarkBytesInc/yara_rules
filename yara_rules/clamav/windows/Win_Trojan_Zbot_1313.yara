rule Win_Trojan_Zbot_1313
{
strings:
	$a0 = { 5589e583ec08c7042402000000ff15a8714000e8a8feffff908db42600000000558b0dc871400089e55dffe18d7426 }

condition:
	$a0
}

        
