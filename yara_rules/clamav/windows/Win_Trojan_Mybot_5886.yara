rule Win_Trojan_Mybot_5886
{
strings:
	$a0 = { 1e93c847b1e1b733d2bffc8e0b7f11b5e118fe478003dbb254020c6a4a83bc2ddf0e75e62ed1b5b726737a06de7d58f65bd1d9bebb46db70601b5df1dc71b2b800755e3ca6cfd0a23bdabefb5b273c4bee3d6e0f1dfe0b3fcfd59f133b1438f2962288ca0dd331a8f49fca8fb393 }

condition:
	$a0
}

        
