rule Win_Trojan_OnlineGames_51
{
strings:
	$a0 = { 75746f2044726f700100064174697661720c014101420c01430144010005416c7a65730100054f736d696f0100094475616c20536c6f740100074d69746872696c0c013501450c014601470701490c014b014c0c014d014e0c013a014f0c0150012d0c013501510c0152014c01000e426f6d626120646520416c7a6573010003323525010002302501000e41756d656e }

condition:
	$a0
}

        