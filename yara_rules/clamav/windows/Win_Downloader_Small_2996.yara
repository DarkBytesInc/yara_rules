rule Win_Downloader_Small_2996
{
strings:
	$a0 = { 6641252427f373e1a5538aac665ae99ee4b82c4d235335dee896535f483a2ce667ebbbe19f5301d96da2a956338ef81bbe8dc771ba501b8a8db7ca3ae6d024106c5884356ba7f2fb99e129c64303c1d7d0b2c66bc46e4c34c6554dbc06a330552bdb6aa4febaab39b7c54bc5dae49f12fd8b }

condition:
	$a0
}

        