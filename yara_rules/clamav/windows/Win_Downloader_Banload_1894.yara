rule Win_Downloader_Banload_1894
{
strings:
	$a0 = { 006600943e17020f5b3fc9e5606723266f024784464dd774cda80e23bec503d4e4000000004db36c9641f000427173e4cd9aed20a4453b367c0336c8ed845771508f2050120000b04c0735dd1f6b7e850394a0b019a4593618481a8200000000bed934cdb22c4b8da2d1764ca6739b6683a5bf4deb03d103d22c9bee1d4ec2cf58000000f1c802d6350b7b18 }

condition:
	$a0
}

        