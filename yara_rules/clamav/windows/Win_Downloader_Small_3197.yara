rule Win_Downloader_Small_3197
{
strings:
	$a0 = { 8d7652e82874a7ee0edb324297719387f77c2c5c26c196e59e786c5c66c1aa1ba34552df26c12c5ca442acd3d6209a586d1b66866fe26c6ad86e658613976c0a4381fa096d95 }

condition:
	$a0
}

        
