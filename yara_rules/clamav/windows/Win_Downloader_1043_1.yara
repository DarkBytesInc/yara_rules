rule Win_Downloader_1043_1
{
strings:
	$a0 = { 040fc13bb104eb8cb65d2818a3c8c00cdf45b2196c9a8afbe8c55b98061db1edc2a1bd54a807930d11f9ed0d0ccc1bed6e80ea32918a887502ea13f71f54dbcdb19bd0b1bd79a24018154cd62b280ced40b5e9ba6274b120e8b51744 }

condition:
	$a0
}

        
