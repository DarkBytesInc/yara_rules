rule Win_Trojan_Pakes_352
{
strings:
	$a0 = { e4904f99604b04f53d1b11b96be72130643c513648889581648455b18182ef071fd52fc4dfe4e7527b8be8baeb8a47cf104414dabe7fedc01b4978bb3a2eec1a07812ce46b84fc3158813d8efa5e1ddf5d74e84e113e14c8a4642f6c4fe59196ec81f4b6fa7aad8d1b2901b74e107328e4597009b20d4664df18e7f17883e0e28a617423b58754baa20098c6 }

condition:
	$a0
}

        