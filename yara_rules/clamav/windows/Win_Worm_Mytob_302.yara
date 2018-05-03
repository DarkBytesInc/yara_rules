rule Win_Worm_Mytob_302
{
strings:
	$a0 = { bfac788daa7ddc9c8ead1babf93e388c99b2ce5ff63076fba88a3dbf1aa5d19f9bf3f554c5489e7426332cb3ea0a8033c0fe8ccd6eefd9e99cb379a245dcfa0c696c602b3231ba728f7d69d6b23d8ae7d7730c80a97706db3456411707e463aca7c44bb34a1cfc4f8a006b75445141df }

condition:
	$a0
}

        
