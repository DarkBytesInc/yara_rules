rule Win_Downloader_Banload_354
{
strings:
	$a0 = { 5dff0000008f0000002f000000009a6a2437f1b13bfffbbc3cfff7b83afff1ae34ffeca630ffe9a02effe89b2affe69829ffe49429ffe39527ffe49529ffbd7725ff9f7f63ffe9ccaefffddfc2ffffe2c5ffffe2c5ffffe2c5ffffe2c5ffe4c09effc97426ffde872e }

condition:
	$a0
}

        
