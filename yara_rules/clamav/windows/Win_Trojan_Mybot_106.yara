rule Win_Trojan_Mybot_106
{
strings:
	$a0 = { 022dea4cd63cc9da8384839d88a810ecbc75566d0c45b31d1814d7530cbc1ec2544f44994441a1d05829c921589553862664683f8d4a6f626f0d144689428a5d1610d1c30cd02a346e18fb68804948633e42b03245a26fb110437c304832a6219379a5ca5dad4021183c4d376f7a28b1612f343b09 }

condition:
	$a0
}

        