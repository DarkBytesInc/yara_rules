rule Win_Spyware_ot_178
{
strings:
	$a0 = { 8a73656b44ddf341dae1804732a32bf37b1f812f58d52e75711e745a788db2ef396598bbd355be1a32404bcf5fe8fd42bf85086a5b689d4738e9a9729aaf89f5f118d39c7fbbad341a5312d343db5d86ff9815654374c00c2bd2f22d5ca5dd60f1a106346327cec15cb548e088984a9506a037b80edcca26ca5f7819beee3c6026275dad98b430af65173d8b1edee60600267e }

condition:
	$a0
}

        