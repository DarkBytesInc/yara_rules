rule Win_Downloader_Banload_1041
{
strings:
	$a0 = { afc983295ba4c0bba6c16b9823df194cd84357b0a698fa81cad9b5138e934ae4b9e97e916491275fa3a5d7d621f1cb2b5e1df8def89b91ecc49f97ceb883f6a6bb31cdaeed72748056215376d94392a8322b31a6978f3caf4176784fe7af0b8d08f648968c90da7f9025c690d2eaf022eaa47b }

condition:
	$a0
}

        