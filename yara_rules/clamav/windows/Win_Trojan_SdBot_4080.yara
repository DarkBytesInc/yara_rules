rule Win_Trojan_SdBot_4080
{
strings:
	$a0 = { 204aa68f2866a09ab4e366ccbe5b9b085c54a53354a3d50c45224138446b6386fbd45e68fef61c277a8e369e7213e064c6762582719b1529021d076f9bd51e99bce627ebba485c5691ca3a47a5bbb3bdd0668f64d21b0435555a562eb70c29affd803bd46aa7225419f1d03a0dea9b50844a84070ce935560b9df05b5931d99e }

condition:
	$a0
}

        