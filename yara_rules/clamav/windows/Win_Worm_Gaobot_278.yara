rule Win_Worm_Gaobot_278
{
strings:
	$a0 = { 645a46476b2fb92df720f26a83e8dc63d28f6c2e8860847a2c5878515275a27e994a31a01fb5c33f81b18b37b301cd83778a4649d25cd8a58b165866b7f4cc239634b1f2e846807eb1b8845702262087eba35a942542200ce933f7a0a1fd6a312264796c7f65a4def894c49014632b8a7564132044d4bc1d3424ca083633d40d2f395aa088bfd61ca9e752df6d2214e55e02387d8870 }

condition:
	$a0
}

        