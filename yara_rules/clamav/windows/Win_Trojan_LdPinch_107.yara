rule Win_Trojan_LdPinch_107
{
strings:
	$a0 = { 5462ff8ce9b81f8380b9594be0c6a94c2d0d6fb5f3fd3f64a763ccfd88430caa48a109ebfe916b45766af50c6f7d5b6d56f457367016e955fce0f5553b4c9b0a1ae0f454fae31605b7d5c337dbcac8b40cf37a92bdbbf7378cd0acedb98821b51bac705a09cb4c915dd0cb2a5ce3969f0fc09a87c48bf91069e497ed228e72b5e781 }

condition:
	$a0
}

        