rule Win_Worm_Gaobot_716
{
strings:
	$a0 = { 447562213fbb40832541c8233b53bf20709436b2e8028b6c6c895d51b1d0eb539fc0ee26b9255483effac506742dccc041ff4b483bf7c20f879425b1d2516d47ee0143d3d8404f699e6d524f415b6caaee8d9e6094110a6005e9d5742c28eb0bc9140b23fa4440b1ca1411bddf8a9248db20089047e24081497af54141a58f5113882a052e446fc4fc047280c12191b7051c9a228925 }

condition:
	$a0
}

        