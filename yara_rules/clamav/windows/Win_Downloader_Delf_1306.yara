rule Win_Downloader_Delf_1306
{
strings:
	$a0 = { 254802920454105191d8ac404201139c921c20dcb8d6dcfc31ef759ad61f867e03dfc33502dceea05b733816dee40c6af20dc582e56f082d2412d75016dd406f5d4836ba835c7520fa6b82e37520b4d406e5d491d5cd41b7b9a80db7516dccd02e77ba6f735aeffffffb79fdf3e7dfbbdf9e7df37f7cf37be73f6f9eff022e6870f255ce083df77edf6da10e }

condition:
	$a0
}

        