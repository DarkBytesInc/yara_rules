rule Win_Downloader_VB_981
{
strings:
	$a0 = { 803c689d9d9d9d0c941c5c9d9d9d9d6c48187c8f20169e78684012e8b358ec600199003040020078317c902ba0c59d7242a2814be414b26a4f0087c5d501ffff0634d10042a2f01900616978614172717569766f063c8289c5701707788e26d62e16401c15a2e50e2cff701b7f8bd308203cdc36c708de1600f46900730056423521f01f2af86037cb7e0a00 }

condition:
	$a0
}

        