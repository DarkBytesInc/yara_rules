rule Win_Downloader_Swizzor_466
{
strings:
	$a0 = { de4f7d886dd7171a9b89f6783879afd43d8fd55a927e65ce0e41f67aeb28130e27beb09b3b8da75de63c3ca3357520f73c4b2410761748692de2c7fa9fda8cb6de9aece7bb23880f5a75083b14a2b65e9c3df67256b55483a959 }

condition:
	$a0
}

        
