rule Win_Trojan_Agent_32650
{
strings:
	$a0 = { 5abd12deb53f1ff1c3de884d161fa3e070595353f104e1592867aa4621227c4e748edeb9e8fbfa1cd88fef2e0b945efb43e43cf59e1f15ab3c4937cf573375161528dd0179642d0899240382cee5c387a78e9473ecce5c7a3ab7afdc47530ff74cafb2aa12ce7361e84374073c61c7173e4a87b3b09784833c3bb852ea12e68f30d87580bb3ff88c3336ac44 }

condition:
	$a0
}

        