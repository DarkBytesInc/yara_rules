rule Win_Trojan_Ciadoor_222
{
strings:
	$a0 = { 1b345c49e491fa98f1bef52c4203e5d1df9fafdb28aa728e28e2c50fe69865cfb5e66ce75329e5e265459309118bf71ff0d9120346afb88dba76e1585b4b771d0835b9be16af2e624e2bd56e683ac4ac573340adacfeadb4ae6862cdd6abdcbf199352cc }

condition:
	$a0
}

        
