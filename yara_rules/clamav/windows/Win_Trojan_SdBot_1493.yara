rule Win_Trojan_SdBot_1493
{
strings:
	$a0 = { c4e53ebb57930cb646a757842fa90cba766bc7a42dee1c7a3de63fe6a36d5d6a819878f532e8b9756704e60899ed395fdf7371eff672a5658ae667f8282630c5f80258bb51505d15a69825b3757b04b85bafe1d43cb48884b35dbdf982eb20f9d9789f617cfbbd05cce6bbb58a1c2861775e5de53ce84f1d68b3a107e82e75e503dda6ff63574ae2ebf1f13565eeac53ec2922fadad1 }

condition:
	$a0
}

        