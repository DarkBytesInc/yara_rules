rule Win_Trojan_Hupigon_511
{
strings:
	$a0 = { c22944e5c74c06c00f0af9a06db3692a44ac495a31a5c8ffe6257b66d2f578c354e7275637b82f9c8861e209c6efdd6dcef6faabf123e01514f619e02082f36803a9c94e1ac590dce175f336d580 }

condition:
	$a0
}

        
