rule Win_Downloader_Small_3075
{
strings:
	$a0 = { 670bb65ea49e42c16ef89e7a2562dc02eda80fc90f089d7764089b74722380e1ce12b24e50a94879d424fe72137549632323c90e70a3955754f084ce2703967272c5bff380a324ac2039d34128b997759bf4478766fbf279b8719e45acf7144826369b7557f2da410ef777969054af7d0b3efac7edebf5637044a4776c373b74edb6ab626a3700351bf5b02d0814a155a2c3fc644194 }

condition:
	$a0
}

        