rule Win_Trojan_SdBot_1730
{
strings:
	$a0 = { 1de1563ae35339dab1e729b9b7307ae4aa4dbb3a8153444f6b5de61d4913da95674303fd587112aa83a13026fe17889824ba06851344c279046b963236ea1e4949a3428da588588ea755af165952435ad3a609c86a244846b26e11826ed43166fb94b617b31813daba13dad4b38e7410e5c4c69c2882b2a493ca68c013d44a7242b9447181526a9596 }

condition:
	$a0
}

        