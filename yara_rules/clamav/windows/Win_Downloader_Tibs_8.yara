rule Win_Downloader_Tibs_8
{
strings:
	$a0 = { 87ed8d6d0087ffba00a24000b9000000098d125287db87db8d128d3f5189db8d368d360f3187c989c90fa28d1289c929c087db598d09e2e287f687d28d00588d }

condition:
	$a0
}

        
