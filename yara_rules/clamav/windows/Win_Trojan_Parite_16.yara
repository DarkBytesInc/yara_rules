rule Win_Trojan_Parite_16
{
strings:
	$a0 = { 39fdbf2dd8122064f77e526a844317d84387338acdea2eef4cc321a9c8ced49e40fe55cf15920917cebae15a73957a4eae7b885660185b58d461d4914ce2dfb5f82f2d6bfc9bedf1bdd1c23ceee6216d3f2ea4136b4865d263cfe594c9864e9c4a72c1361bf2f29666b70f161cc9da9c40e7be272b67bc480ce8c4fec26cf87e288261aeba3c860864bee68f }

condition:
	$a0
}

        