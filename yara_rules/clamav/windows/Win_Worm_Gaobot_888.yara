rule Win_Worm_Gaobot_888
{
strings:
	$a0 = { 68f6455b6370b6223ba2fd8be80848cfbefd35eb586559ff4da13f480271b47222a27c77703663bd88e7b1ef185617fb84e065c278112bd97956b2c9ade093006e3d025edf25cb4b839a0d77110d993978b4c3896c534fcfa2636858ca905ae28fa6e321caccae8ee35b4cfa334e5e504d81f185d51ef6dc994fe35bbf60d8e40e29395872ce431369e53029a185a8 }

condition:
	$a0
}

        