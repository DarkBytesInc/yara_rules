rule Win_Spyware_700_2
{
strings:
	$a0 = { f2f293bc5b93d81e031df58e77418ee002b0093ff84b170ae52ca1747f46077032eeb95c47676430b6dca5f91b6fae14893cfc89582631860bbca9709b6691919a0abb6d9c1344e806338ec12d25332e654c102cd08ae9659284148a7738f9cc6b76e916eefab62b6e708dee581410235b062ecc30e89e8c708b8d57f5d49fe24a1d3518f4e81fb8 }

condition:
	$a0
}

        