rule Win_Spyware_Banker_2681
{
strings:
	$a0 = { d9f8e124b611ca2530db4c48c9b48eb88121fb4162c7abad2c0c651db577b454b85f11915b237e2d0f6dea762bdf11609dc88cb020e687b52340f9a412724ac820adfab746a3620766a5d2f53fc5 }

condition:
	$a0
}

        
