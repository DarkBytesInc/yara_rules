rule Win_Downloader_1175_1
{
strings:
	$a0 = { 7d7b04b68c07e82a2285ac23e078e0e8ea8bcb0c07b83d8eda08b8c6a5bb8be4cf23faa2ce0a5557e87af708c095bfd205cc7773d900b640e89b5a1f4bb5dd04dd8dbb755b45bd3a03b8b9dd1074d9f63045be3703c1384bf36f75bc }

condition:
	$a0
}

        
