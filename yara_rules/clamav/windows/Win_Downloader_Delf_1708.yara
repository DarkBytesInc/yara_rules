rule Win_Downloader_Delf_1708
{
strings:
	$a0 = { b94c774000ba14774000b802000080e85edaffffb95c774000ba14774000b802000080e84adaffffb970774000ba14774000b802000080e836daffff }

condition:
	$a0
}

        
