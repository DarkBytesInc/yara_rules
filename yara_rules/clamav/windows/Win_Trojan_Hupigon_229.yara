rule Win_Trojan_Hupigon_229
{
strings:
	$a0 = { 37cea9b9c5292acc057dd2fcacf71a085104c0c39dbc438b725eed7b6caeef71b1f4fb79479ef5f56527d875de2fbb43a4f719085fa2d3b1f1cf4c1c64724d8f80669ab3255dcb4930c241648f3d88af39e60271bddf6a6fc82511a5ff5bcf040c5db73a80797c6e8a3f54ab0352 }

condition:
	$a0
}

        
