rule Win_Downloader_Banload_819
{
strings:
	$a0 = { 5472524afec7591663eaa955cf95b5d69e99e3f396638399d33050ca7d4d57b1b6f281eefc171495c62bf0b12aa2b41afd57a727454c7efc45aa1505b00905d22aa0f330826cf0a2b9593a6b536d49311c37244d111b8b418168634e921d639a90a5b816c5a80615ae65227e1cc52bd791d8a19924df2cd8065a65795dc4b39df59e }

condition:
	$a0
}

        