rule Win_Downloader_Small_1486
{
strings:
	$a0 = { 0d5aa1a0ebf2a9ef85e5cc0875bbf2d7f2ea00cd2c310501458174f87a3ef17a7f77b8c2c38bffbfc2f38a12c2f48a16d2f748010181e48ce4d2f8c2ca8ceafaa4c2c08af0d2fdc2c18af6d2f2f58c010101118076f9bcb97d04fa82417d11fa75f93e1efc742a3e12fa7e1afdf43acd }

condition:
	$a0
}

        
