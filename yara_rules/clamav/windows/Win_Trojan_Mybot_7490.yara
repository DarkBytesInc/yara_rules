rule Win_Trojan_Mybot_7490
{
strings:
	$a0 = { f41dbaef458629264586191ba1f7f51af602306128117eaf857346b5ea71f3d99370e6b945d95b06253727bd359fad606695ff4cd312bf0fc5814044a69c9d3477eadb99d55029510f26f71bf9d519d7950b74dc2c3d89abcf6af6e1df60625017657b4e78cc3427b1db3938f858d0aab3f574fc89f9ab46bfb72c13b2367bb7 }

condition:
	$a0
}

        