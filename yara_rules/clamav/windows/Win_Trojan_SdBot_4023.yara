rule Win_Trojan_SdBot_4023
{
strings:
	$a0 = { 0192ef7c4536bb1ff126f426a202362b596e0ea72d8386d143daf0b3eba34c4be17ee5c4e3e0ab1d966dfa5e8ef10051b9b9ee6eaf3a29030e131505d9c795dceab9aa1668c800b0f2ac4633b47cc05cbcff30783413 }

condition:
	$a0
}

        
