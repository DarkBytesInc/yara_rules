rule Win_Downloader_Banload_606
{
strings:
	$a0 = { 6b6a74a2173436718ef0040da48295fb24c845b8c0833c63621841a1d1e50a5c7cac6c3229d01bd22953b4b2e2afe4c2ed69eadbddb3815468952292ee8c9a8fd250138a653b0af35ebfe62a60229c4a5fce00 }

condition:
	$a0
}

        
