rule Win_Trojan_Mybot_5347
{
strings:
	$a0 = { 883cc982c6d16a95757de7f94165edf5ba18589d10a9d2a0b2f5781e914adaab8db9c8f21708f3a78600ee7d7bf9aafcddb674ccaa79ae1f90e5a076d5b9053464d5423f784c9a1ca80cc1fccddc08610a07613ac4af323a1dfc7a8ce0cd99b88f86c1957f56082f779ca58452a7a2e9ebe1a2c4a6e9090f5242fd24108e1f240e6ccfa93f542f669b93ab2f759905286a1785362036 }

condition:
	$a0
}

        