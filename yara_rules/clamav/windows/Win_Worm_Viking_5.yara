rule Win_Worm_Viking_5
{
strings:
	$a0 = { f5accad71575768a122609ea6e2ff3ddcc48491bb4827d972709e13dfa61afb363190da36efcae21ecefd0d2058697cd4431f4009bf7ed1ddb0a8149712e99af14f1abd32f6a63e3826a8f55998d99f4decc1c73f32ba988bc7e300c0bfa31729e7e392a40f2323c7c0519c08b58e3b4cf1427326dd23b2682ae8d2665f3e83abb88a1190e929cde73e182c1 }

condition:
	$a0
}

        