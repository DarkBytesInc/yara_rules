rule Win_Trojan_Bancos_644
{
strings:
	$a0 = { 6ec858a92aeffb6249bd900053bd2cc8188c7126754a32a19bb8b574f45053fce431ecb2facda371d8de5458f531673e12a3a41d54bf192bce680aad0d7e77c3ebfd82ad3a889813725056c40ee040a8d969b0e781f4a1e7b9f8 }

condition:
	$a0
}

        
