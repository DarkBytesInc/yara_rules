rule Win_Downloader_366_1
{
strings:
	$a0 = { c90110c70601df020080c17580f5498d354ec9011083c60480e94a66c70600008d354ec9011083c60680f5a966c70600008d354ec9011083c60880c94983c600c606c08d354ec9011083c60883c601c60600b2978d354ec9011083c60883c602c6060080f2a080ed6f8d354e }

condition:
	$a0
}

        