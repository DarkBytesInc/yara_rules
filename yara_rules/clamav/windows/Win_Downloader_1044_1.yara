rule Win_Downloader_1044_1
{
strings:
	$a0 = { 2d4b944a509a2b0afbe9d836662ad75ba23ca22a55417bd5a2fa858de265330819aab631c0bf36d73ccbe19c03b6b607059ed90a01a6afea979e008e94a19eca73eead512c1543981bd02109c02be9489bdd1a9f8d6dab2aa6bca6f5 }

condition:
	$a0
}

        
