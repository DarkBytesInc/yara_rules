rule Win_Trojan_Delf_1038
{
strings:
	$a0 = { 2663c1699b425940fc519cbc101377ec3d4edcfa61ee685c021cf4d9d1953ebe736319c519f8d7e53bc352115efe988941e99c2590da46734afca0ab034879653ac606b25acc43b97dd96e6cc3b2be61cefce6026dc70e6bec }

condition:
	$a0
}

        
