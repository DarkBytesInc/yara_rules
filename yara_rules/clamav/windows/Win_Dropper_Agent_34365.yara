rule Win_Dropper_Agent_34365
{
strings:
	$a0 = { 8d45fc508bcbba010000008b45f8e802eeffff8d45f88bcbba01000000e833eeffffff75fcff358c76400068b04a4000ff75f88d45f8ba04000000e8d9ecffff8b45f850ba704a4000b9604a4000b802000080e8b1feffff }

condition:
	$a0
}

        
