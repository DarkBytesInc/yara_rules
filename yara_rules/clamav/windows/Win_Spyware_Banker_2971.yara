rule Win_Spyware_Banker_2971
{
strings:
	$a0 = { a60dbf04d9f98b6c1e55ffa3882d91e236d74b01c44554b68a703e078a54ea1bbc7b02a79bb9c834985a84988257de7e22534678cc4f6aec640374f1f433d62ef7e2b4b6c36b3ddcdd27804b06c2980492eb59b367ddf4037ed4bddfdcc75fdeae4ce75c }

condition:
	$a0
}

        
