rule Win_Downloader_Banload_892
{
strings:
	$a0 = { ff12098a0156c5a0bc423a056c9964e5bebd4b12a381a1088900dbb450d8c30ac28633640200830ac3002097ee5400fbb35c027580c5d89d080a9087019c7b097d044e24f0122c71856ca57a50c2b26ac53e809feed8a8c13ad1173938cc96599b9b101123d4a9c2874c2b97b22d59c686351b80654119e5c080591ba88b121dccdc7afc04495c6984655a6f }

condition:
	$a0
}

        