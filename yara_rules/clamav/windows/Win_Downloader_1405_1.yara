rule Win_Downloader_1405_1
{
strings:
	$a0 = { b82ad21b15ffd01015150ea11115150e180d15158ea65aa6a68ec22cb1ab80a615ab9251acab1d5b5e52acab9aa6a6a61d5bba52acaba7a6a6a6bc1d5b8e52acab58a68e6b57acab8ec23eb1ab15abce51acab368ec22cb1ab8ec23eb1ab15abce51acab8e9252acab8e }

condition:
	$a0
}

        
