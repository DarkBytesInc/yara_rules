rule Win_Spyware_Banker_5700
{
strings:
	$a0 = { d5e844cf5ad884ade3d1a28dd6370144eeca125d4b4b49be474b5ceef17f6b5ebaafc7b7fae06613f86d9258afca1ffa2a4a067e3047dea9c15f8162114d5dc4ec2beac50eb48accce6c753d12e031ebeeaec73112473a16de67 }

condition:
	$a0
}

        
