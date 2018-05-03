rule Win_Worm_White_2
{
strings:
	$a0 = { 616d20493f0d0a49276d20776f726d3f0d0a5e5e0d0a6d61646520696e206b6f7265610d0a6279206b6f7265616e2e2e }

condition:
	$a0
}

        
