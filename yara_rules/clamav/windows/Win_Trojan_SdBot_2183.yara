rule Win_Trojan_SdBot_2183
{
strings:
	$a0 = { eaa443af2e3a148f43315bd76898caf5af4b045050ba3ede256b21ed7e557abb4ea62bcbf235ca3381c40a8be07b41f6082c142fb8dc6a46e3511b8b9a70059a7d7062010986b2e6d89aef20f6d042acb13d27e30aeaadad3afd6e191cf62cb8d8d1359be3e322ef30f4b5fec74af3d3a5fde2b60c04ec632cdffa69e13acadd9dc03fcdb82466d20d75 }

condition:
	$a0
}

        