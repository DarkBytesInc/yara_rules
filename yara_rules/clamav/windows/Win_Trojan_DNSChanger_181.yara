rule Win_Trojan_DNSChanger_181
{
strings:
	$a0 = { 9f87722d4ae1382252f9e81f5ea428b85105e5b76793f8f752e552c0516739b7258f1ec874cfe8424ae7e7cd929f28b8ddc414c8928f50f468cfe80e5166e8ed66b128b8a98ebf0f51a518c8928f2808a9f9e92152f7f4cc928fe72d4e8ffec762cfe8b6c78be8cd5a9f28b8b1ed43ea1259ac0ddd7b6ca4721c2eb0a8c2de08bace }

condition:
	$a0
}

        