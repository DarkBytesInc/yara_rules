rule Win_Downloader_567_1
{
strings:
	$a0 = { c2fdffff290066c785d6fcffff300080f6b280c91c66c785d4feffff6e0080e94bb53366c78562feffff630080c6a380ce5966c785e8fdffff2e00b1f466c78522fcffff760080cab366c785eefeffff650080c9d780ee4c66c78510fcffff670080ea8f66c78562fcffff690080ca9966c785a4fcff }

condition:
	$a0
}

        
