rule Win_Downloader_Swizzor_539
{
strings:
	$a0 = { 591a84d372fc5a7ceeef80e6d8f56bad8e5ad4428fc3eafb7da9b5e9c3fc988c450c008f95adef07cc0e0f58ae8a0dd25580f1940bea34d932efeb714a9edac1b0645a86003d5262480301e9ae21011f14db03fdc29bc4eb7216d75e1c4b62f73a712b5a56eb806298dc05760b7980da3a1164c6fdd5ed17 }

condition:
	$a0
}

        
