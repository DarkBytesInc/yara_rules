rule Win_Dropper_Agent_31747
{
strings:
	$a0 = { 58096a5af0baae92182516d24b5a498782402f6778b3d149bdd79671214be1934d6b7289c9a1a11c4f5968f916e4c3c324622316ddca22708e50a440135989f82d5a038db8ab71e893113e2ea0efd3efc47d49bbe088314f072c4517f6b08ed313a9708b8a761eb245be0dccbd60df67e8163ece409b8b75e1d4e8281a5cf972bda178ab309436c035fe8e7d }

condition:
	$a0
}

        