rule Win_Downloader_Banload_1729
{
strings:
	$a0 = { 44705ed111eae10f1eb55986c0bc1b1e05d7fb8836cb63b6b0ff7fc9d20ed958ad7063b9ef169b38ced94428ccab4e5457731366d119b6a92f44ea703faf39f6cfc4289d90265befb8af0d17f99099fb1f03f5c6c4d017335f2a0a1f871a9bbbc1d9495842199b12335730e809a43887cd970dff9be6febd8ff03824d6b0f541d82e899e87399481f91d95cf }

condition:
	$a0
}

        