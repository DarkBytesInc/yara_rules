rule Win_Downloader_434_1
{
strings:
	$a0 = { e82ad6c7f20bc0d2b8e86702f8ae73f062ba61b68923d7a58fa7dd169ecd41ab6ef8c82f62916c61f1fdb1d969d368ff78b172c3bf3bb919346a8f848a938b7186978bcf4b6626040f0cadbae49176a17e28ddd6e68f12af051d2c01928e4242607ec813ac32bc62b8595dd1598509be5fc962ef8462bc011106328652384f31 }

condition:
	$a0
}

        