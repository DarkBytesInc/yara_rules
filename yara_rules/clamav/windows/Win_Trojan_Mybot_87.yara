rule Win_Trojan_Mybot_87
{
strings:
	$a0 = { bb073c29e86bdef520fabe8e3b55a90d958797fa86bee7595d59ed0a7de4d027b2ae2ccac86ddceb29725ff4ddd4b81adb998aa23eec431803b9d44ef1caf65f7a44653043a0afc9fbdf86eca3af29022c5f9f848b7c56b069feeb0d9092f22139389b3df12acdbe }

condition:
	$a0
}

        
