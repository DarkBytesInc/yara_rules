rule Win_Spyware_117_3
{
strings:
	$a0 = { 4bb722e5d527c339b86709def426aa0ba084ced239c2b4e3166cbd0f9dfe8d12d1df6958cfb9d8febf1b3bb4bb24e9f03d6f10de13f972a7e0bf784f904bd7174efe53b4cace9aaa71aa56b6e1c5bae40368897515fa0f47ef75ab }

condition:
	$a0
}

        
