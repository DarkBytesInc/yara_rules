rule Win_Trojan_G_Door_1
{
strings:
	$a0 = { a3bf00b1f9bad30000c7ebd1a1d4f1d3fbb2d9d7f7b5c4b4b0bfda2e00b1f9bad300c7ebd1a1d4f1d6f7b4b0bfda2e00b1f9bad300cfb5cdb3d0c5cfa2bcb0bfdac1ee000050617373776f72645061676500c0facab7bfdac1ee00004869735073775061676500bbf7bcfcbcc7c2bc }

condition:
	$a0
}

        
