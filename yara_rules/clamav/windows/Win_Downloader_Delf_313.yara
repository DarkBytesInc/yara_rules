rule Win_Downloader_Delf_313
{
strings:
	$a0 = { 37ff353e7443183dc2b2980a9b28ba042a76495f639a34289cc4ad4cc91207f3c5b8eb042603039b2f651c063b93c073010b15040e89076773906d671c12019b692bd321052ef0df687474703a2f2f32707f7375 }

condition:
	$a0
}

        