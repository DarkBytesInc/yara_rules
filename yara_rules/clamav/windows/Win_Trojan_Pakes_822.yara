rule Win_Trojan_Pakes_822
{
strings:
	$a0 = { 5f269c8963d0cdd5a2a0c1a9dc3c7212df8581187b113e62df1d7e913e18bce7c86a7ba6083ab4346c10bb8c5c10949fd3ddbdac25c5b4a2cccea98ba977b6ecc01677c6dc1d27128b16e660e9e3c4af82cdb920ce87beba9fbd7b3e783a427957171f99e9bff55dcc6ed19775a9971a5fdfa1f931939446089eb3d16b18b3c439b79e032a1d7f8c21964aa9 }

condition:
	$a0
}

        