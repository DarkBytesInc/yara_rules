rule Win_Downloader_Banload_1737
{
strings:
	$a0 = { de1de5f3ae117aad687bba471e32fce2d029154cd7e0c10f14edd395263c328e13e266298eb27723990de2019bb46943d9ea38b536f84b90c03a9c3b627d959e6b53a71165674d7b19ca49986f47cceb0413f0e0807a6e6dd2af88d254c3d2c2e9071e0a643dcaca933e203e594906e5dd2c0d5c10be5293551a00103ff9ddb953e0883b9f845b59cbbb777a }

condition:
	$a0
}

        