rule Win_Trojan_Agent_33625
{
strings:
	$a0 = { c3352e42d583c6825b5f9ada1a85018433e23bea9969714041c706500d97209a943f0925bf2480138ca77e128b1714b4a5e5cbb2f796d46ebae9e25dbbb9d07020c35f6695fb89a85ab44578c22cf0ebd538 }

condition:
	$a0
}

        