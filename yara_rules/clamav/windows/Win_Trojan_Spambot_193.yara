rule Win_Trojan_Spambot_193
{
strings:
	$a0 = { de20ce42f29bdb637f957e9ca223ffffffffe609bef3a33d57640dc91fd32f1590edb84710ccc4e25468478314026ae0cd8fffffffffd0f9912d08e880ea24ebf6c77bcadabd03ed8787e44738be9848a3f1cd542870c0ffffff0f61e5e25002d7a16bd86013f6035f74d125cd03 }

condition:
	$a0
}

        
