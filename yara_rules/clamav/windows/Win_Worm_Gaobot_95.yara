rule Win_Worm_Gaobot_95
{
strings:
	$a0 = { 6a1b586cb3c35fb8ade6c6d52113e102b5e7a9340bdfccf22182db92a3ee6fafd52bb6eee320333b3d2b9724806f7d18babc92dd9489f3ec3b34483789ae5a3813290b86e013035a72796bc4e900ed30d730b5943d2279d936a84dece235e77c7557a4ace224df16f3529887d7dc0809f83696cd6a337be222b861c31c7080816d7d9c28dc7aef1215bc }

condition:
	$a0
}

        