rule Win_Spyware_Banker_1731
{
strings:
	$a0 = { cee20142ff4138af12df4bde8ccdfeb462af5df95e16c9209f85f09d42b2ed7cb8a08199c0ee7b25bfe84894e61f73f8602eb365b50402dc1fdf19e1c5e35831b6186153ae5a6fff4cbf8a8b921ba4a6d55f5502272f48b62a3e2a0150f4adfd07614b9b52c029bb77fcb4b2219ee139cef671cac909b71a364a38d2b385262147c496f667955f5d79b312302ff4fdba5e1a388c }

condition:
	$a0
}

        