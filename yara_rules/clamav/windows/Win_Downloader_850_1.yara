rule Win_Downloader_850_1
{
strings:
	$a0 = { cdc912cf546e9fe8de434d113e540ae9fc3d64e6f8c5080134df7cb656c4180461f82ab7009c7d1564e237e00ee0a3f8b1e18f8ee35b4474cf160ae5b5a9e703e86a23138802f2e131b1b40d99ac52d021b1f599a4832cebdeb5159bb0b2d5e619b024b5491f582e397875540fd4834cf9c48f0246bad74df9ed6c0b }

condition:
	$a0
}

        