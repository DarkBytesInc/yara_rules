rule Win_Spyware_Banker_3377
{
strings:
	$a0 = { 6a4771a843b79da0ddcfaf5d8cd0c5cb23a930a568f5375db0d07e51a4e0756f74459447330cbff27ec3af465431e198f9e21822b9ed2b8323accb6f64509a96537750eceda94d5da86aad825eec1c31cac2d8fb8d55e5103df88366 }

condition:
	$a0
}

        
