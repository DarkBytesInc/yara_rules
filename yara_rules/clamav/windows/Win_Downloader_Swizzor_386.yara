rule Win_Downloader_Swizzor_386
{
strings:
	$a0 = { b09fd69e9a85f785e4628988e4e15dbb0fef9d2d50bdabcb95e1654fe5b35f51f2152a27639c1c60a20eb3d639d48c79a0677df1edb6ac6b91a1318f235cbdee3cd7e30dffabc209d78e9b359a66e5918329d6b01683d68cc064 }

condition:
	$a0
}

        
