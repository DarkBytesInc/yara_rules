rule Win_Trojan_Robobot_111
{
strings:
	$a0 = { 7945d5900d870fc1c4c6c0c2e15cdbb4a0239d1eed0ba4de3ce1812c9ab3a975837784a39509a7e8ecf6280c5e8c655a06d1e584fd7ca809cdd66fbc3ef070d88d761b6379803e7686d30f4f173793e8ca13153991fac785a1d1dd070abc4cfd151a6c975f5ba9f60f4706031fa4677d381b7a1f62eb9bf5002dcf7708fb374e3423223d7bfc7e4c6266182dfe83d2e3ba2ec6662fb0 }

condition:
	$a0
}

        