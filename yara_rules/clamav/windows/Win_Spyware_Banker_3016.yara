rule Win_Spyware_Banker_3016
{
strings:
	$a0 = { da298ed0bd9fcca15e9cc6ce796f19d885823ac11b9215e6efc9e60cfc3752b03a52190e4a45a864cdafef1ab6c0176ca8b618165bd613a28652159f15333ad302cccee447f3e379ba9222301d7b6d00cadcf15b7be7feac3db2b05ea32b058416a490ae }

condition:
	$a0
}

        
