rule Win_Trojan_Downloader_126
{
strings:
	$a0 = { 666f7228723d303b723c736164667364662e6c656e6774682d3533323b297b2f2a736b6c6a6764663d7366646a6b672b323334332a32333433 }

condition:
	$a0
}

        