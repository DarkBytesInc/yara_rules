rule Win_Downloader_Small_1044
{
strings:
	$a0 = { a0e2736d7018018a65416201220e108a29011b4b968467f017441fb23d5e7846756e4f696f6e4d7d3362c282621f01c358728042159144c48c61d37cb2ed36b0b4186c65396599ac2dfb6c77fc7172748b0ec7a248d8b640643fb0762b9cebe28b7266d1461215a5f645780a5024ab88c93672b5c7310801e309ffc802bdd63bc8d658ff34cc46504d55c4cc30035d5a4611939401ab }

condition:
	$a0
}

        