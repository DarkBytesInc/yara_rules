rule Win_Downloader_Zlob_2149
{
strings:
	$a0 = { 7f66667b72b031f3be4bf18eebd7bf8cf8226ab9fe2eef48fae3a392311dcb2bb356ef54ebba6dfe4ae2f9fadda1edee557d98daf8daf8ce6bb4a7d8f90f4e1beedb6da1f68466676f9e2a2e761a58e6c036b94d8fb9b4e5f5ced6590f26dd2912cea38bce7f0c6f65723e714cc5e9a67b0f3aaa555c3fbc7df1f18218bb }

condition:
	$a0
}

        
