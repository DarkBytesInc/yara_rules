rule Win_Trojan_Bancos_1176
{
strings:
	$a0 = { 62e4bb98b7c989641f195f9afbad112b56b8e799a6943b897accaf40c6d7d3f4e7af9ad3c603868755deade7e8f92642ccb827c1405c2662b42d1bcf7e96a891a49bbe3b6f1a04681a5e71696ee4953ba11e6b09886d203f87a9 }

condition:
	$a0
}

        
