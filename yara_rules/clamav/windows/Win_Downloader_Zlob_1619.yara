rule Win_Downloader_Zlob_1619
{
strings:
	$a0 = { 0d954350afe9e123c5a45a83b6c3c78c7a7cece7fdcc1dd5bb906e6cfd13cbec4ca5420bcdddca4fc110485e11ac620aadcbd26c649b8cbb30f99621b3729c0500004f8683be9f184d8f8606544d96a4b275d5acf611ee30ba1177b2e5ef7ec5d0b25797a122be05252f0bad526b7f4f8566c425987914d155849114ea80d29859f5284f76b39a7534d8c8b9d5ecf8cb0af0edd0d7f1 }

condition:
	$a0
}

        