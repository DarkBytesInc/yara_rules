rule Win_Trojan_Agent_33620
{
strings:
	$a0 = { 2217e83743fdb5024bdc474009d99d6201cab48c87c76d8eacb77a58c221483f53c51dc57c803bc00198cfd4853d2d2eb1c68b86a4d2e159fbd1a76b0ff7cb92ddc46529a1a605773563cb92e8b4fae4b223 }

condition:
	$a0
}

        
