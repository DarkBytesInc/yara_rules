rule Win_Downloader_Agent_31847
{
strings:
	$a0 = { bf9e0f68da9d46c3bf42fce825a74832fd83ca57251c2362f575593784bcad2b076bbd52f758445404e874fd730aefb21dffb14b82d4182ad83c231ab6990845a4c50085a87a06ea60e47e }

condition:
	$a0
}

        
