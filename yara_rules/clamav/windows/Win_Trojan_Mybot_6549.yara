rule Win_Trojan_Mybot_6549
{
strings:
	$a0 = { ff3d833b86dc8d91a9500026ccff393a8fd40c8b7bd106c2fc66fd1fa312c76a9389bbed7f10b8a58ee513e8b2122f1b7287989ecbb168b9fb5ff5c32e53c68e03383834cf4d3d9374719ab543cc50fad3e8071427ef503c6dde761994c30fc995c040a254c9c31423dd8f1de7d8a3baa3e2d9f8a59e288df60e18068d58316869a690f14387e117c6dae4ff41fd19db7b46210662fe }

condition:
	$a0
}

        