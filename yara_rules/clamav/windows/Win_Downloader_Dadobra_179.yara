rule Win_Downloader_Dadobra_179
{
strings:
	$a0 = { 9abd0d5c54c7d53f7e77f7020baeeeaaa8a81849ba26e22b8826e0425c85457c4157de44148d096cd010b570af2f09c8d29586cb484bfb247dd27fecf368356d9ed4b6e4a5114d9a2c2c01893641b48a62225193602e4950a92c4adcff397367173446cdcf8fcb77eebc9c993973e6cc99b93373798399d304ccdbb8313f77ed061507ffe81ff0f54b5c9b5f98cba715 }

condition:
	$a0
}

        