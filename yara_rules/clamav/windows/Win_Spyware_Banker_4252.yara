rule Win_Spyware_Banker_4252
{
strings:
	$a0 = { 9f6e791649851d351837f47eb8c9dfe22230b2a42e24c268723f95823f614870d2a0c43aa4ff54f16804ce45f7a40af4eab77f2a9ca57ab6fe0bab43becc0b36abe684c492ebd1a25c29ea08a8da0af010b0032f9a63e8bc4620b5a5f66d7fe3c42bb9b5b866f52faf00def11c64bde48bc1c28956bb12f35cbda3ce17541774e40359fccc8639b5c84de77e }

condition:
	$a0
}

        