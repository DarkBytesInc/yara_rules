rule Win_Trojan_Bancos_1057
{
strings:
	$a0 = { db93f56fe936a9cab24408e4571522577cd2bb08c840164d151ddd30bd9b60f1275688286c8d4264d52d0effe401d24a998f4cbcd07e6537825134dbb5764776713dee3bf0ff37d4e6cbf4c7a88fddfd6facbe6b55714f8d }

condition:
	$a0
}

        
