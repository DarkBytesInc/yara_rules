rule Win_Downloader_Swizzor_600
{
strings:
	$a0 = { 307e98bb69cd3ca389db1396bbfbcf23dcd9f19c275d5c5d3d4c27fc0a124c8829dd230d86a9008eedfcb7dba14aeef4989eff11dd24bf18418cfb67845b9011249f0f2fe289c674c13716791ada1900ed61f9b264f029a3a655b4e0d2b1f6184114fb5c590d67c2db }

condition:
	$a0
}

        
