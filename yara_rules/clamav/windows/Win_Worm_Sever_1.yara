rule Win_Worm_Sever_1
{
strings:
	$a0 = { 322f66cb86fd517569636b4874178c766bffca17477269736f66bc8e473633afeced53765065721d6e616c675472ac6d57 }

condition:
	$a0
}

        
