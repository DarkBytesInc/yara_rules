rule Win_Downloader_Swizzor_397
{
strings:
	$a0 = { f881cf7b10685a03ca7804b819a6a865be4c29c6b066da83b7c4901fdadd0421213137b7fefd80d0b9f4bbe800fd2a302fefc7e552b0e4bca299a9da91ff615c7649308c3bf93d3f1889b3b62f26dee62bd72d4069a8633bec0d }

condition:
	$a0
}

        
