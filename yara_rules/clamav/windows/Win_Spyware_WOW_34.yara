rule Win_Spyware_WOW_34
{
strings:
	$a0 = { 2ab51a0c803dd127bbff13eb4e1e5a97b4cdcfe635b16ecaaf27fd7cea8c6f2d8ec7c08253725380a250c5653d45e5cf520974c904f4224d401a6961eeafce3663fe285c9e7a78617d8dfd797b70d0d220e8e42a49b52f56e2939d34d62efddbff03e56837192ec7bf8a854584e968ab417f0d2532212225b81e7a268481a3b2 }

condition:
	$a0
}

        