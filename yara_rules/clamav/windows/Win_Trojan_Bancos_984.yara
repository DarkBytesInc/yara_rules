rule Win_Trojan_Bancos_984
{
strings:
	$a0 = { fe2b8d95fb1f8a747e7cfc8bb9e8e90c01ba4d08b6fc9fa64fe31fb63c101268ffc71e3b32d3fef17e6e86737f40dca57c30a0e8e7c9a226a4cd8532f4324990983fca59f63a607275484e506f2924cb9180d60b0df83c27 }

condition:
	$a0
}

        
