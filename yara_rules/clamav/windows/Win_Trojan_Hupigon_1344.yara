rule Win_Trojan_Hupigon_1344
{
strings:
	$a0 = { ce10d1c362549d68d9c62d5a3947fccc7eec24e813dbee36e15d3bb808e70e17c47374cbfaf07215de0a451c1dee4788a3f3e41fa506c7eaffd8aa0283665a9a51ebbc7a91d8165e97efff0c7d5bb0b094a2b43db823c3607a305c0905651d52a30f }

condition:
	$a0
}

        
