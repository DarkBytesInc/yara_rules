rule Win_Trojan_SdBot_3920
{
strings:
	$a0 = { df8c7a41d8c1f33c914d72a175392abd80db276e882c8ddf0c98215a04126bee51c7c7ee5dfb44cbfbb11dfefbd36dc5946dbcd2e86c3faf9fd612482854f42636dfcf6799ca1680991b4af90eff88b287fb45a83aff55704f7c7ac0 }

condition:
	$a0
}

        
