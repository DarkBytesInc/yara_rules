rule Win_Trojan_Proxy_66
{
strings:
	$a0 = { 47467cbe92cec7a3eb2f64803a254fdbc52e840eb13fceec4f1df3e9b1135a8c1b3e3984b38f52de014d84648e0ed81cc16bf8c1afff8db741e528d1680404ae567b7302136c8e0ce7a83af3e8c0a385d94b3e5e752635a4f0c8cc91 }

condition:
	$a0
}

        
