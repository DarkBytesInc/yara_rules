rule Win_Trojan_SdBot_3658
{
strings:
	$a0 = { 4af2c44aebbc31a5156ac4c1d1090c321f8ad19c928cdffe97a45c38583a0058e28ea890a2b7c541a1c39437de55d353ea1e65f08d1d206291a7b4d77fb3f50c476ede8144386c4a563e19907eb8 }

condition:
	$a0
}

        
