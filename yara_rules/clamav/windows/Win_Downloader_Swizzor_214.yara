rule Win_Downloader_Swizzor_214
{
strings:
	$a0 = { ffe2d7cee2a566792036569e5c7609ad3f9fb29be1efd808c3057df9bc6063b032117befcab92fd6e58748dc79bf31fb27cf8d70dbc1acceb7ef19a0799b12a2a177849b51f61386b639c326edf791745d066a56af3a8b1445ac60fe123ffa03ecd9c4e7b601767a83744e7b68efe5b4449a3dfe0f4e370672f23b602c202848f79e4fde284bb393372ccc07561324bbe4a4335ed9c6 }

condition:
	$a0
}

        