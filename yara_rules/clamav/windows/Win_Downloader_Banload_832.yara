rule Win_Downloader_Banload_832
{
strings:
	$a0 = { e53f79626327e81365dab95bc5070b4da7f36d6074aa57f059facf8e67151a38079f8b6269a4b23ccc0b57eb4d7c0508a7f76f8218b73b4da892e90b61ffa0adbf07a4627d540b69bfe2323c04b2927a }

condition:
	$a0
}

        
