rule Win_Spyware_Banker_3369
{
strings:
	$a0 = { e9e7ea8d180376be0f8525b0a93cc16332d04c703d0c0391e9f4abceea8c7e551f8d4aa996d451b5322470ec4890f3d4f3a0028d60f93a9f7b7a526b3e01ff409330f41becd7781dac165ee782c5f077bbb33cd786 }

condition:
	$a0
}

        
