rule Win_Trojan_SdBot_1285
{
strings:
	$a0 = { 470d5574d6fc73bda4edaadfb8000000005dbc7244b3c412d340d986ec8c7394a462c493186e5cf71854cafaed31e7940000d065de989055d9d3ef415b9a2236b4f58bca25f7262e000000009701a69dc293d5829b7dab8f91591e060000099fee }

condition:
	$a0
}

        