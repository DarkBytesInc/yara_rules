rule Win_Trojan_Agent_32910
{
strings:
	$a0 = { 62782f93e95ac6ab2e90f43e28add1c8ca4d22e83b48b652733abf8793bd8a9a752a5ce4e5cf0c37843c89d305b191aea99ad6e557972fc9fde0246b1d6251e0ba4d1ff6ff1ac8cbd678e8c15b5298ff428bbde427 }

condition:
	$a0
}

        
