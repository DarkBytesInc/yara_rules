rule Win_Trojan_FakeAV_137
{
strings:
	$a0 = { 5589e581ecdc01000057568365d8005355c745f4000000008d5df453ff15606e400083c40485c00f857e01000053536a006a0053ff15846e400031ff29c781ffa9fff87f740c81ff81fff87f0f85ddfeffff31ff897de8897dfc579d31d289d681c6a1522701f7d64629f7037de8897df489efb8a8010000f7d801c7897df031 }

condition:
	$a0
}

        