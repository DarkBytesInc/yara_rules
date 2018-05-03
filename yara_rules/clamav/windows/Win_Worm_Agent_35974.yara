rule Win_Worm_Agent_35974
{
strings:
	$a0 = { 646f776e6c6f61642e747874272c2027746162312e }
	$a1 = { 246578656e[0-16]646f6a696e6d6f7269312e657865 }

condition:
	$a0 and $a1
}

        
