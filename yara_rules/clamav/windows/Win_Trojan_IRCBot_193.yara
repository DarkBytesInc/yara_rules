rule Win_Trojan_IRCBot_193
{
strings:
	$a0 = { 6a0c7df82873733f1c8d711a87a677138c4e9ad849373c3e8ab5a4b5fc88fc0ca89068f34802d7b1c8a08654d5c4acdeb096c48fac528237c8eee0d6a214addab8c274dffc68b63739fbb63f6d40e2207b808c4f57b57d5e9fa07e8422a7acd13097d64f1dbdef06734a721e51c5e22df5ab945572c40bae3d1328 }

condition:
	$a0
}

        