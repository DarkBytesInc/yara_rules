rule Win_Downloader_1607_1
{
strings:
	$a0 = { 13550d3cb954644deadd828da78c559dc28134d3d105e1221ae0e9537176446298b4eb2bf33922a7b02d5de41a0c43945d0a476714d4af2ea43dce54b461eeba1221b274069244f0d4b5913549015b1c813f19140d6b98760d3d11c48f68fce01dcf6f9b3363b5498c681a2b757d1792ce254e71b5301fa7bf077eac59fa4b8fa2258e9e8065bbe99672d349a0010a45bbf63ff3 }

condition:
	$a0
}

        