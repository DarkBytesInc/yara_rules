rule Win_Downloader_894_1
{
strings:
	$a0 = { 08bf2e9b041320ddb08aaba43644c6fe873d900417c8ff90ec88ee6fe404191ec58065f0a0aceca5a990d321880860f0742194f06cdc3da5a4e466adbc63da84e430b6f5d2f6307479037665ca59119a5edf592390f721f4bb5090f88bec68808423d0ef4a6b493567083ff63aa4 }

condition:
	$a0
}

        