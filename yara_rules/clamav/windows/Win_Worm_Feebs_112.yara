rule Win_Worm_Feebs_112
{
strings:
	$a0 = { 52dd8ce31da1edac6efb5ae1e156fcfbbf9fc1de2d318891cac7e715c4f3974ec1969625e19494ca4065a41720817cedf8824a726b7968a4055cb545d200aab9e50c27c765eff0bd9051e48fe37051e1f180bd48d2049965f7cc87c29fbb0baf93f03ae1dde6b705106b97f3bdd78ae15e94c14f0f53d44bb5a7f2bc948131363fae58e2f6f1aba21a2be0572257f86b23275c95 }

condition:
	$a0
}

        