rule Win_Trojan_Mybot_8403
{
strings:
	$a0 = { 9ff84e5571e567ebacfba6af4eb3de03a1f6a1a84ae0206958ee070670475f7d83e8315da72c51184cb5c68f5a59e4f435de8185a0819d1e067fd4bf333406ce9921787aaf74e7c5da1e37fbae0a9ef1245b481e62 }

condition:
	$a0
}

        
