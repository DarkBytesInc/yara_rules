rule Win_Downloader_250_1
{
strings:
	$a0 = { 9bdb132aa8a9adc81bccee51f81912a6c0e6b23c230da2f4973531b5b1b43f1df93a6670fb21025b2102a2deeb867bc74426424dda40b5dc5becf30629bd2c169cfb9d94a926e77ea62b5b1b431ba5889a98ddf07793135b8dcef672af7f67c956da710b625aba3c7d76577b4842d555126ec72caad3c0f136e67f729eb3af1ae8cc83bdc04a64415dd7e87895442747baa3a13a4739 }

condition:
	$a0
}

        