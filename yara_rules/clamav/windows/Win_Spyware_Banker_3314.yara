rule Win_Spyware_Banker_3314
{
strings:
	$a0 = { f2c0d0f84f446a7cd8a3ab724d83f4fa9030a99c80e813d566e9d4f45ad2e2f04e1ca39f90ba58b945bbbc3c34422a8daeb53645a10fea07f66e075a6c3c3288b50262c5004b68b1703f7056a19b061ffecb484c1e }

condition:
	$a0
}

        
