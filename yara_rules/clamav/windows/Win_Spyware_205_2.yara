rule Win_Spyware_205_2
{
strings:
	$a0 = { 1a0897834cb0829524282dc179913f9771a422870649b91ce345f6237b790050583ed8be5f444d3863fa04e92a1d59c5552c92186c8d05b4c3983243c1351c5f54afdf551e9fae4411f753d8f690de43467b1cc03311e78f3cdddef3a2957b2f1a17317479e0fec8ff419be3e73ec4f404cfa4f07859758bbaf134d8d8a4c708817319c1f002c4a1e142b1b9a75f4de4dee55dfecfc6 }

condition:
	$a0
}

        