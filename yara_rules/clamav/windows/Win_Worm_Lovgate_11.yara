rule Win_Worm_Lovgate_11
{
strings:
	$a0 = { 9d2fdccfc8972ee2ec3eb1b4d494fc96c3fa3ffe7c20627139ccebaecff6a8263e167f54d7f3f92403092e615b68817a135cf6b36d7c0c6a41c8161821ef0f2650879ebf5e175f8cae4b1e04815ac4e5ddc7524aa2c8f4369e731cdba71bda51 }

condition:
	$a0
}

        
