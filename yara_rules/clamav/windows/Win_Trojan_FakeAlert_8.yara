rule Win_Trojan_FakeAlert_8
{
strings:
	$a0 = { 558bec81ece8010000b979000000c7048c00000000e2f7b99d51ba76e8000000008d450033c5400fb6895bb14309d1e9648b419f50b9d8fe00002bc46429812801ffff8144240435000000f4648f0500000000c9ffe0568d742410ad5e8bd08b82ac000000488d4a2c89818000000085c0750a8182b80000000100000081c224 }

condition:
	$a0
}

        