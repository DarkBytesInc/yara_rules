rule Win_Trojan_Mybot_213
{
strings:
	$a0 = { d8762e4b03003f5cf87c0967b0170e28657865ff6fffbfbdadc3f1c9b1b6bec8edbcfe204832303034a3bacab5cab1bc7d36fbefe0cad3b761764d6f6e2b0b436c61a2ffff5220cceccdf8b7c0bbf0c7bdb8f6c8cbb0e6bd57c0ffc76170706c69635e0fb21f }

condition:
	$a0
}

        
