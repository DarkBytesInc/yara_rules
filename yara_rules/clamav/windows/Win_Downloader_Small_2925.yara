rule Win_Downloader_Small_2925
{
strings:
	$a0 = { 74b6fed57c68033566b6bc0b90b60af1e53240b50a0ec80bffefe4d402a888df02b2d3badc16c02ffcb6465d02854bcd5f5ae0bb7eb6fa2eb0a4a94006dce090ba2ee0f13cda5d25f330577adf62e042e22119f300818bc482e6037580bd1125a6654db00c68fad09cea0f7aa95bd699e35c }

condition:
	$a0
}

        
