rule Win_Trojan_Mybot_8370
{
strings:
	$a0 = { 83d1f3fd500a65f3b7d665a1b705a7d9c51f72678db0f417208fd6400cb7fd2aba5705a17a3dd277bf7791f5c3feaf6ca632b3fdbb6bbeb1f16602d7f5fce91f47d99bc6e03c3774011d61e667d3db73dcdd424513 }

condition:
	$a0
}

        
