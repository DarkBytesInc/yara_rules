rule Win_Trojan_Mybot_6114
{
strings:
	$a0 = { fc2c4ad559b2fccf2c0010df15bffdbcad8f8bf8c085ff0f840802a6bb7ca46b6a300ab66f694adf5342b59ce02ce0c89033efb0cd1d3c83c72bd345ddb1bb7d8db7d7d0eb3e8bcf79467bf0b50fdaea8184352c83743e3017f6ff7f11248bc6996a1059f7f983fa0c75b283bdccaa6712c3dea47911c803 }

condition:
	$a0
}

        
