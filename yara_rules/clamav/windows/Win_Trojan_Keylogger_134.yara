rule Win_Trojan_Keylogger_134
{
strings:
	$a0 = { bbc9c307e39a684ce88ff90734bdfe484410353d9c2696886882114dcb2ab766400870b5a5a5c5558a8c2f98adf73f5b75d5b11c9cb05f7decb7b4bee8d8cfa0fca35d75ecf74adf1e8064c135b4bfa3f0ea63cf40d919ece5b1efcb6c6419423a547388db6d699eb57bc14df35557c8 }

condition:
	$a0
}

        
