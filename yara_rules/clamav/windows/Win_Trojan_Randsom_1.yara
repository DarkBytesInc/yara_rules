rule Win_Trojan_Randsom_1
{
strings:
	$a0 = { ec245356578bf133ff8d4de0897ddce8b78200008d4decc745fc01000000e8a88200008d4de4c645fc02e89c8200008d45e057508bcec645fc03e8f81effff8d4dec57518bcee8ec1effff85c00f8462030000897df0897de88b1dbc004300baecb6430085d2c645fc05746452ffd38bf0468d043683c00324fce8a88800008bfc56576aff68ecb643006a006a0066c7070000ff1570 }

condition:
	$a0
}

        