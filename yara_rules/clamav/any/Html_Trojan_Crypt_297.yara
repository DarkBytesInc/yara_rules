rule Html_Trojan_Crypt_297
{
strings:
	$a0 = { 6e657720617272617928293b766172206e3031343d3130303b766172206e3031353d6e3030342e6c656e6774683b666f72286e3030333d303b6e3030333c383b6e3030332b2b297b766172206e3031363d6e3031352b6e3030333b6966286e3031363e3d38297b6e3031363d6e3031362d383b6e3031335b6e3030335d3d6e3030342e63686172636f64656174286e303136293b7d656c73657b6e3031335b6e3030335d3d373b7d7d766172206e3031373d303b766172206e3031383b6e3031343d31303339343b766172206e3031393d6e657720617272617928293b6e3031395b305d3d6e3030312e6c656e6774683b6e3031353d6e3031395b305d3b666f72286e3030333d303b6e3030333c6e3031353b6e3030332b3d32297b766172206e3032303d6e3030312e737562737472286e3030332c32293b766172206e3032313d7061727365696e74286e3032302c3136293b6e3031383d6e3032312d6e3031335b6e3031375d3b6966286e3031383c30297b6e3031383d6e3031382b3235363b7d6e3030352b3d737472696e672e66726f6d63686172636f6465286e303138293b6966286e3031373c6e3031332e6c656e6774682d31297b6e3031372b2b3b7d656c73657b6e3031373d30 }

condition:
	$a0
}

        