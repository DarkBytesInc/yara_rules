rule Win_Downloader_Small_3422
{
strings:
	$a0 = { 499ef2c81487e247840cdfff8fffbba26facca1b30d5981780e1b3dcf2f7bb26601a2a7063bf9da6ae2a1959694e814021a51f5b05e0e14a5889c2a6f1d3f9165ef38f5f8ab2db3a747cdbac3e8ed8cd892698df8a8aeb03989fb69c7be6620d2621d58de71eaef0ba49a470924566 }

condition:
	$a0
}

        
