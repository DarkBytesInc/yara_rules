rule Win_Adware_Search_19
{
strings:
	$a0 = { 8d45e88b55f8e816003e708b55e8b82cae4400e8160030bc85c074298b450866c700ffff8d45e4508b4df4ba14ae4400b860ae4400e816047e488b55e48d45f4e816002be8 }

condition:
	$a0
}

        