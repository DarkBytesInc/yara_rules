rule Win_Spyware_Banker_3457
{
strings:
	$a0 = { dee24a58ba5b8260eead37986241a5ddfa8c77475ed19f992cb65b78234a94521aed98a4843ddd73a2e63e8032951cfdfed32eaae0d1450302a218660c1d07b43c8edfb818f3ae929edd6d83ccb3d39b985186bfc2c2687d41b9d8ceec9209 }

condition:
	$a0
}

        
