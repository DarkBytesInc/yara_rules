rule Win_Spyware_Banker_3443
{
strings:
	$a0 = { 245fade82c21af7e211c0a49b3c22a4273e951e8e96bb73ed6bc58208f7cece4b71ad3db0de58226c647ecbb913c149c792f822c86aa2cc94d710abd64f938fab3a956f672569b87599fc740bcf871faa273f49b2e625f3a10bf0345db9786 }

condition:
	$a0
}

        
