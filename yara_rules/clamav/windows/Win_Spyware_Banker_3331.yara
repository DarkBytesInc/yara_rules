rule Win_Spyware_Banker_3331
{
strings:
	$a0 = { e20c2a6a71c9727b698aaa16bff52cd2bb3bed79cba7588f5952e905c48cc5ef6af5b93357542baadde6c066486f930609aac7fed5d24954137203f62eb81aedefe4437a734b739aad683d5515a2c4805151a65784 }

condition:
	$a0
}

        
