rule Win_Downloader_904_1
{
strings:
	$a0 = { a1ea81ec6f4074593d33506a9ccf037b5fe4df7052a605d3cb99a5f3facc9d1b5576b8128fdea4fa47ffef50625d7c3f5f4b27dcbbe6b836effa2722fed9b7b07e929d484d1b48c8f91144c340539e41f70f0a07ce3179700a60f8f36cdffa }

condition:
	$a0
}

        
