rule Win_Trojan_Bancos_999
{
strings:
	$a0 = { 99a12a2e5bd8ba7875db83bbf5a4c4a8f0667a6de80de0caf4895b4dbc3997cd7db4ea5cf2ea54f3a0ad386b21fb0db54ebbda81c689263932037118e22df542273dab09e0335ee4414d95e02eb1659054195e1a45 }

condition:
	$a0
}

        
