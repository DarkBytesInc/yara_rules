rule Win_Trojan_Hupigon_1547
{
strings:
	$a0 = { 7922accda1e02f6584bb4baecfd2c3d83e50c55db48614830829bceb2b121d3a0f0d09fb7c4c388a16044c7f494d745e72b717118f9eb18b0e6449ec82769642f9686e850a0933fbe469d6e4fa51 }

condition:
	$a0
}

        
