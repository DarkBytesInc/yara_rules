rule Win_Trojan_Prorat_38
{
strings:
	$a0 = { 5defcd387fe1fae8ab3ebef5f79f128723ef4e403f639ea42b1ece3b3f63feab6dde88973d0fdeec2ad38fe77b4a9b23ebcf2e403f63e76cfa5e4b385faee1acfbde133b1b0fd0a165d9d28726ef8ee7db9fca381face72cfa3e5267aaf7df2cfa5c92261bf2df785ee35727ebd92e433c238e17f89fde2cfadb12a783f70df748a3 }

condition:
	$a0
}

        
