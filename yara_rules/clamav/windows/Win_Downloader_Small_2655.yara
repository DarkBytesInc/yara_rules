rule Win_Downloader_Small_2655
{
strings:
	$a0 = { 8bf885ff7433681030400068a020400068702040006801000080e81dffffff83c41057ff15102040006a0256ff151c2040005f33c05ec21000682c30400068a020400068702040006801000080e8eafeffff83c4106a0256ff151c204000 }

condition:
	$a0
}

        