rule Win_Downloader_Dadobra_259
{
strings:
	$a0 = { 7d9316a852bbc766a8dcb6dc02feeb72e70f9d265ab2e2e8f68f852a3960008107b39d8e669d17bc9a84f9dc90586a56249d430c314ece1b8953152c714a25c23fe4236e3e2ac47ec51631254d607df61470afe1578cc34916af0ffc4312e817f567f5241d81467ec20a55794261ff5251f726a2d130f37ec4d92581028d9e492d46f734a8b284fca8fe16fa }

condition:
	$a0
}

        