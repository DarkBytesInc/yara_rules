rule Win_Trojan_Longbe_1
{
strings:
	$a0 = { a1d8410ef7aa3995ae5ebfccef399277de844a8e677bea5d38bdee19cb28a3d47ceaa4371eadf1ad98f558621cebed3389ac43602abcdf21cad68ead5d6b9c2517a5ae1d10321bcbe5eb7d3b6df918016eff256ce397b74ee5ea3897f5d397bf9173abddfdcf0f6139f36d2935ea535fc6b21cbe75782c1d }

condition:
	$a0
}

        
