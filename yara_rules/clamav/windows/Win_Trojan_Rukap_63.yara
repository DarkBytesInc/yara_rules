rule Win_Trojan_Rukap_63
{
strings:
	$a0 = { 1dd9dc05fa9aac1c2a70887ad81eac83ff67cf7fa644434183a9741fa8f0741be1d934479424595e8d5b695eac0000bf14111b90448c57333461d4c0c172ff57e8968353fcc8e2ea }

condition:
	$a0
}

        
