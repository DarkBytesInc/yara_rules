rule Win_Downloader_Delf_1155
{
strings:
	$a0 = { 9170378802763657e8b72dd8aacfe29b624b3682a5260405ea8cfbdec4cd0d81132882aa947f42206a25a96e0e287eea7c492678aba0216746bf7372f24ccf4ccfb8c631e4cef23ca7079d1f70342dbba5 }

condition:
	$a0
}

        
