rule Win_Downloader_Swizzor_444
{
strings:
	$a0 = { b0d0207fc8304e330afe2f3dc61489afa546fffc76c27a5ec7ca560d54d6b352eaefa2274f9fd8b7da6c4e49c0abc431d11712e7e2b8e485936c4c02154075c46d97adf390cba801a000e7c2ef44e57322737d3d38eccd6df3fa }

condition:
	$a0
}

        
