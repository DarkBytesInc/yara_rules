rule Win_Trojan_Skintrim_18
{
strings:
	$a0 = { 979cd60c17c630a7ecc696436fd8e5f044a988cacd9206f5e322bd023d1e4e0ed7388434e82cc2e13ea37b2d277082a97d44d988c441162dd1a5604f49c955ccb65ca15709b4875a572cff22e19049ee8ccad9c7c073321ab8711c5f77138c573c76dce39c54414b8a52db09665735636010362315db2e7bfd0f4372c0f26e164fc5d6000a40b4677d34c657 }

condition:
	$a0
}

        