rule Win_Trojan_Mybot_7747
{
strings:
	$a0 = { 243249a0b3ac9779969240109ac6424b4088a2ed00ab840bb7bb629d3d0d42daf8107fa1b49f3bf7f2d9d33b983b42b4740aaaa9d16c959d486e5848cd8178e7ffdc8ecddd0ad85fbddc5368edea36dd200c78027d8dc5a4c7784d042e8c8aea6a600d3415ae }

condition:
	$a0
}

        
