rule Win_Downloader_Agent_31711
{
strings:
	$a0 = { 506830120010682412001055e827f8ffff8bf883c42885ff75136888130000ff1564100010 }

condition:
	$a0
}

        
