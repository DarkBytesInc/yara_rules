rule Win_Dropper_Agent_33510
{
strings:
	$a0 = { 7c7223976a2f2d9946d5160134ec31ebca5ac35feb6d0e61c9ae7d24c1cac1e8bd3f98ddea4643a292d94b6f5ba10b3acdc4f69074a78f5206654d3eefaa9fd40e8da4191174e491f5a4bdcc2b5e0c6f69321f81 }

condition:
	$a0
}

        
