rule Win_Worm_Bagle_275
{
strings:
	$a0 = { 6130a9841cde2028bfbb1044d0736d59da2b66977df5147daefff079e265a87b6ac8ea3c73bee3664a59a42594557046b7377b3fa2e713bad10080a2f5f0542b9a26426d2d45c3b8f6983fe19abb7f38542d12fde0476bbc00fdf1da9d0f0c4c68eba09ad2db163385f1da5b19c08eb97484c12d1fb324201eea23605f9342ca2d79ecf461b84653b6e8b013ad011bde4fe7923165 }

condition:
	$a0
}

        