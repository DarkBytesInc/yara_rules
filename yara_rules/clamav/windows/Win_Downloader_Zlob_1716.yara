rule Win_Downloader_Zlob_1716
{
strings:
	$a0 = { a41255a385ad9b6a0904bea6b568c370915eaa47c1d56ab67ebeda7bfef8ddb96643cb44acee155684156568dcde7b2216303c3e445b9ff6e17850cf539bf0e55bc74272791078473b354d65dd6cdeeea23e5a8bf96e126b0971 }

condition:
	$a0
}

        
