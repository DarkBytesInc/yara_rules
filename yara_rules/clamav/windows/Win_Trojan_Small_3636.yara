rule Win_Trojan_Small_3636
{
strings:
	$a0 = { 6ce42a9a3951778315d56d5895a5f5c63a2deb1f81b0a885149d2ce38f622f1843eac7a4d6370803be9aa6f3de362b946b301d8aaf30a642efdf455d3f56a97a7adf7c3a041b170fc5155a20378a74eb46e7e55e9bf0dff757b7 }

condition:
	$a0
}

        
