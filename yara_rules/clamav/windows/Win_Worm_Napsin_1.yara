rule Win_Worm_Napsin_1
{
strings:
	$a0 = { 68fc1c04e8cd03eea7ff07a13b300338b3801c38db9f1db5429673ff249cfd08c512bf6d831501d353696e61707073fffff208fbffcc317ca50d5d6173664ca391513b73a6b6ffffffff4fe57f2ce4b4c9794ea86107a7694aaf7b3a4fad3399 }

condition:
	$a0
}

        
