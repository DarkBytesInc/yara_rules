rule Win_Downloader_Zlob_2155
{
strings:
	$a0 = { 77c3df49dbadbe2e2a4dbf77503ebaebedcaece55b693d37cd59463c5abd3dc8fa66d5abc9cd2f14765fd16012d727332dc72b7a5e8371ad8f5f3e5a5222187c83cf36bf4a8f3ab3e1e9d60ed9b7265cdb26994d979e7c1dd2defc64e2e88a63ad76ee75a0555c3cb0f9c7b2e2286e44 }

condition:
	$a0
}

        
