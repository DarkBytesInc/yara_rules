rule Win_Downloader_Zlob_2113
{
strings:
	$a0 = { ff80dd778ffa6c42e878668121fdd5c8b52fa53cf2c2370b1ead0b1c2bca6a4cccac0af8d233625caf179fae9b55f1aed27666c20b7ff9479e97beed91e4597c69d3e72f44cfcc19bb7b4ff520b32634f1c298f0bbaa077e5cdeef4ce0c777fce976fa4dd1899dc7e778eefcb9dee7e7 }

condition:
	$a0
}

        
