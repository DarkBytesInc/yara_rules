rule Win_Trojan_Pakes_805
{
strings:
	$a0 = { ec31bef4709075a8afc060d4695c105e6c132064484fe40d6c3b24dd0b485e9a95f61ddad5655647595059dfe94f36d3807b65bf32d35ccd798ac9d696215d7f8d421dba693b4d5c38420c0cd6736cc24f8b594b7b1165c52ce61e326566e004044145e3d6df9c10792a70ea62b7c265ec78c1841ecd373ad5b9569c584851b706e1c56e173b25e02ec2e9d4 }

condition:
	$a0
}

        