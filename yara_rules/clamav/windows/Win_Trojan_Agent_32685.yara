rule Win_Trojan_Agent_32685
{
strings:
	$a0 = { feb63da7bb47c23fe9f55496b7bfec676c304c877cc56a7b9ef93f1fddab1e5e6d5c5a784a7c2b790ee0f9cc58b30a5af6939a892f2d72fc3358bac286a1c7789b0c34434b5eaadef73af970325d91fb3ea22b3e3cf3edd9829067dde975c436cc895edb1bdea8afbf7d79eaa944b3 }

condition:
	$a0
}

        
