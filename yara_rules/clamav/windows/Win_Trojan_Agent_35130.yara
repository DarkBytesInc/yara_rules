rule Win_Trojan_Agent_35130
{
strings:
	$a0 = { 1b0541bd496697663767f9a601a426ddca26afeb016b0ef0353a0c38de8fc35c776d1f242a4ff6340d476d457fe4ac8b305e8ca068e78d1425270aacb757d2dc43fa2f4f7b6832ee8e53232cf050a8c4 }

condition:
	$a0
}

        
