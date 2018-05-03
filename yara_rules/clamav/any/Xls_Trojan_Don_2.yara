rule Xls_Trojan_Don_2
{
strings:
	$a0 = { 444f4e2428343229203d2022a5a5dceef3e9f4fcf8ade9e6f9a9aeb3c6e8f9eefbe6f9eabfa5d8edeaeaf9f8ada7d7eaf5f1eee8e6f9eaa7aeb3c9eaf1eaf9ea22 }
	$a1 = { 4f70656e20225c444f4e2e7478742220466f72204f7574707574204173202331 }
	$a2 = { 6a3024203d206465637279707428444f4e2428582929 }

condition:
	$a0 and $a1 and $a2
}

        
