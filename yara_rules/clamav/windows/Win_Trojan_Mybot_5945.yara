rule Win_Trojan_Mybot_5945
{
strings:
	$a0 = { fea549cbc15bd29ea81e84b932cc325f0755bea84a4b117c3ac167af6ac3e425c01ef609169f9f58b954bfa40f81503376d8b3eba60b17f3c2f80394719743e9ecb5dcbc361edb9e08109af1b111cd006837ffe0b82a51f721f507996ef40a24abcf5d3ab3c3fed5 }

condition:
	$a0
}

        
