rule Win_Downloader_Istbar_98
{
strings:
	$a0 = { 7301d793546574997e62d7c5789f042c78f78d76bdf3d78113f473481088c992de0a83f8c55281e3083b652e295d4c68443ed9cf6297308820b09ef445d9fdde6c713221ab54ac60c249a5495f09868db955786e5331b3d5903c121c34e0275fd27e8e41db18cea8399038e53402ec4c4ea1e097f06f8a1263305b7dadf6b1a0679d67ee39047f07cfd9fe41a575d389bc983cf181 }

condition:
	$a0
}

        